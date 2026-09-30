"""Opaque approval grants. Only token hashes are persisted; no signing key required."""
import hashlib
import json
import secrets
import time
import uuid


class ExecutionConflict(ValueError):
    pass


class ApprovalStore:
    def __init__(self, runs, clock=time.time):
        self.runs, self.clock = runs, clock
        with runs._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS approval_grants (
                grant_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                run_id TEXT NOT NULL, tenant_id TEXT NOT NULL, plan TEXT NOT NULL,
                executor_id TEXT NOT NULL, approver TEXT NOT NULL, expires_at REAL NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS operations (
                run_id TEXT NOT NULL, capability TEXT NOT NULL, grant_id TEXT NOT NULL,
                status TEXT NOT NULL, PRIMARY KEY(run_id, capability))""")

            conn.execute("""CREATE TABLE IF NOT EXISTS host_leases (
                tenant_id TEXT NOT NULL, host_id TEXT NOT NULL, run_id TEXT UNIQUE NOT NULL,
                PRIMARY KEY(tenant_id,host_id))""")

    @staticmethod
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _plan(plan):
        return json.dumps(plan, sort_keys=True, separators=(",", ":"))

    def claim(self, run_id, tenant_id, approver, ttl_seconds=300):
        """Atomically claim a waiting run and issue a run/plan/executor-bound grant.

        A terminal retry returns the existing outcome; an in-flight retry conflicts.
        No external mutation is attempted before this transaction commits.
        """
        if not approver or not approver.strip() or ttl_seconds <= 0:
            raise ValueError("nonempty approver and positive grant lifetime required")
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT tenant_id,status,payload FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if not row or row[0] != tenant_id:
                raise KeyError("run not found")
            if row[1] in ("SUCCEEDED", "ROLLED_BACK"):
                return None
            if row[1] != "WAITING_APPROVAL":
                raise ExecutionConflict("run is not awaiting approval; execution cannot be replayed")
            payload = json.loads(row[2])
            host_id = payload["plan"]["host_id"]
            if conn.execute("SELECT 1 FROM host_leases WHERE tenant_id=? AND host_id=?", (tenant_id, host_id)).fetchone():
                raise ExecutionConflict("host has an active or unresolved execution")
            conn.execute("INSERT INTO host_leases VALUES (?,?,?)", (tenant_id, host_id, run_id))
            token, grant_id = secrets.token_urlsafe(32), str(uuid.uuid4())
            expires_at = self.clock() + ttl_seconds
            conn.execute("INSERT INTO approval_grants VALUES (?,?,?,?,?,?,?,?)", (
                grant_id, self._hash(token), run_id, tenant_id,
                self._plan(payload["plan"]), "sre-executor", approver, expires_at,
            ))
            payload["approval"] = {"approver": approver, "grant_id": grant_id, "expires_at": expires_at}
            conn.execute("UPDATE runs SET status='EXECUTING',payload=?,updated_at=? WHERE run_id=?", (
                json.dumps(payload), self.runs.timestamp(), run_id,
            ))
        return token

    def reserve(self, token, run_id, identity, capability, arguments):
        """Validate all scope bindings and reserve one use per mutation atomically."""
        if not isinstance(token, str) or not token or not run_id:
            raise PermissionError("valid approval grant required")
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            grant = conn.execute("""SELECT grant_id,run_id,tenant_id,plan,executor_id,expires_at
                FROM approval_grants WHERE token_hash=?""", (self._hash(token),)).fetchone()
            if not grant or grant[1] != run_id or grant[2] != identity.tenant_id or grant[4] != identity.agent_id:
                raise PermissionError("approval scope mismatch")
            if self.clock() >= grant[5]:
                raise PermissionError("approval expired")
            row = conn.execute("SELECT tenant_id,status,payload FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if not row or row[0] != identity.tenant_id or row[1] != "EXECUTING":
                raise PermissionError("run is not executable")
            lease = conn.execute("SELECT run_id FROM host_leases WHERE tenant_id=? AND host_id=?",
                                 (identity.tenant_id, arguments.get("host_id"))).fetchone()
            if not lease or lease[0] != run_id:
                raise PermissionError("run does not hold the host lease")
            plan = json.loads(grant[3])
            if self._plan(json.loads(row[2])["plan"]) != grant[3]:
                raise PermissionError("approved plan changed")
            if arguments.get("host_id") != plan["host_id"]:
                raise PermissionError("approval host mismatch")
            if capability == "execute_approved_patch":
                if arguments.get("to_version") != plan["to_version"]:
                    raise PermissionError("approval version mismatch")
            elif capability == "rollback_patch":
                patch = conn.execute("SELECT status FROM operations WHERE run_id=? AND capability='execute_approved_patch'", (run_id,)).fetchone()
                if not patch or patch[0] != "SUCCEEDED":
                    raise PermissionError("rollback requires this run's successful patch")
            else:
                raise PermissionError("capability outside approval scope")
            if conn.execute("SELECT 1 FROM operations WHERE run_id=? AND capability=?", (run_id, capability)).fetchone():
                raise PermissionError("mutation already reserved; replay denied")
            conn.execute("INSERT INTO operations VALUES (?,?,?,'STARTED')", (run_id, capability, grant[0]))

    def finish(self, run_id, capability, status):
        with self.runs._connect() as conn:
            conn.execute("UPDATE operations SET status=? WHERE run_id=? AND capability=? AND status='STARTED'", (status, run_id, capability))

    def operations(self, run_id):
        with self.runs._connect() as conn:
            rows = conn.execute("SELECT capability,status FROM operations WHERE run_id=?", (run_id,)).fetchall()
        return {name: status for name, status in rows}

    def complete(self, run_id, tenant_id, status, autonomy, payload):
        if status not in ("SUCCEEDED", "ROLLED_BACK"):
            raise ValueError("only verified terminal outcomes release the host")
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute(
                "UPDATE runs SET status=?,autonomy=?,payload=?,updated_at=? WHERE run_id=? AND tenant_id=? AND status='EXECUTING'",
                (status, autonomy, json.dumps(payload), self.runs.timestamp(), run_id, tenant_id),
            ).rowcount
            if changed != 1:
                raise ExecutionConflict("run no longer executing")
            conn.execute("DELETE FROM host_leases WHERE run_id=?", (run_id,))
