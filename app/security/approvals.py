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

    def claim(self, run_id, tenant_id, approver, ttl_seconds=300, *, worker_owner=None):
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
            if worker_owner:
                conn.execute("INSERT INTO execution_workers VALUES (?,?,?)", (run_id, worker_owner, self.clock() + 300))
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

    def finish(self, run_id, capability, status, result=None):
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE operations SET status=? WHERE run_id=? AND capability=? AND status='STARTED'", (status, run_id, capability))
            if result is not None:
                conn.execute("INSERT INTO operation_results VALUES (?,?,?) ON CONFLICT(run_id,capability) DO NOTHING",
                             (run_id, capability, json.dumps(result)))

    def result(self, run_id, capability):
        with self.runs._connect() as conn:
            row = conn.execute("SELECT payload FROM operation_results WHERE run_id=? AND capability=?", (run_id, capability)).fetchone()
        if not row: raise ExecutionConflict("operation result requires reconciliation")
        return json.loads(row[0])

    def reconcile_result(self, run_id, capability, result):
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE operations SET status='SUCCEEDED' WHERE run_id=? AND capability=? AND status IN ('STARTED','UNKNOWN')", (run_id, capability))
            conn.execute("INSERT INTO operation_results VALUES (?,?,?) ON CONFLICT(run_id,capability) DO NOTHING", (run_id, capability, json.dumps(result)))

    def renew_worker(self, run_id, owner):
        with self.runs._connect() as conn:
            changed = conn.execute("UPDATE execution_workers SET expires_at=? WHERE run_id=? AND owner=? AND expires_at>?",
                                   (self.clock() + 300, run_id, owner, self.clock())).rowcount
        if changed != 1: raise ExecutionConflict("execution worker lease expired or changed")

    def release_worker(self, run_id, owner):
        with self.runs._connect() as conn:
            conn.execute("DELETE FROM execution_workers WHERE run_id=? AND owner=?", (run_id, owner))

    def recover_grant(self, run_id, tenant_id, approver, worker_owner):
        if not approver or not approver.strip(): raise ValueError("approver required")
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT tenant_id,status,payload FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if not row or row[0] != tenant_id: raise KeyError("run not found")
            if row[1] not in ("EXECUTING", "ESCALATED", "WAITING_EXTERNAL"): raise ExecutionConflict("run cannot be recovered")
            active = conn.execute("SELECT expires_at FROM execution_workers WHERE run_id=?", (run_id,)).fetchone()
            if active and active[0] > self.clock(): raise ExecutionConflict("execution worker still active")
            payload = json.loads(row[2])
            original = conn.execute("SELECT plan FROM approval_grants WHERE run_id=? LIMIT 1", (run_id,)).fetchone()
            if not original or original[0] != self._plan(payload["plan"]): raise PermissionError("approved plan changed")
            lease = conn.execute("SELECT run_id FROM host_leases WHERE tenant_id=? AND host_id=?", (tenant_id, payload["host_id"])).fetchone()
            if not lease or lease[0] != run_id: raise ExecutionConflict("host lease missing")
            conn.execute("UPDATE approval_grants SET expires_at=0 WHERE run_id=?", (run_id,))
            token, grant_id = secrets.token_urlsafe(32), str(uuid.uuid4())
            conn.execute("INSERT INTO approval_grants VALUES (?,?,?,?,?,?,?,?)", (grant_id, self._hash(token), run_id, tenant_id, original[0], "sre-executor", approver, self.clock()+300))
            conn.execute("INSERT INTO execution_workers VALUES (?,?,?) ON CONFLICT(run_id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at", (run_id, worker_owner, self.clock()+300))
            payload["approval"] = {"approver": approver, "grant_id": grant_id, "expires_at": self.clock()+300, "recovery": True}
            conn.execute("UPDATE runs SET status='EXECUTING',payload=?,updated_at=? WHERE run_id=?", (json.dumps(payload), self.runs.timestamp(), run_id))
        return token

    def operations(self, run_id):
        with self.runs._connect() as conn:
            rows = conn.execute("SELECT capability,status FROM operations WHERE run_id=?", (run_id,)).fetchall()
        return {name: status for name, status in rows}

    def complete(self, run_id, tenant_id, status, autonomy, payload, *, worker_owner=None):
        if status not in ("SUCCEEDED", "ROLLED_BACK", "WAITING_EXTERNAL"):
            raise ValueError("only verified terminal outcomes release the host")
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if worker_owner:
                lease = conn.execute("SELECT owner,expires_at FROM execution_workers WHERE run_id=?", (run_id,)).fetchone()
                if not lease or lease[0] != worker_owner or lease[1] <= self.clock():
                    raise ExecutionConflict("execution worker lease expired or changed")
            changed = conn.execute(
                "UPDATE runs SET status=?,autonomy=?,payload=?,updated_at=? WHERE run_id=? AND tenant_id=? AND status='EXECUTING'",
                (status, autonomy, json.dumps(payload), self.runs.timestamp(), run_id, tenant_id),
            ).rowcount
            if changed != 1:
                raise ExecutionConflict("run no longer executing")
            if status != "WAITING_EXTERNAL":
                conn.execute("DELETE FROM host_leases WHERE run_id=?", (run_id,))


    def escalate_owned(self, run_id, tenant_id, autonomy, payload, worker_owner):
        """A superseded worker must not overwrite the new worker's outcome."""
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            lease = conn.execute("SELECT owner FROM execution_workers WHERE run_id=?", (run_id,)).fetchone()
            if not lease or lease[0] != worker_owner: return False
            return conn.execute("UPDATE runs SET status='ESCALATED',autonomy=?,payload=?,updated_at=? WHERE run_id=? AND tenant_id=? AND status='EXECUTING'",
                (autonomy, json.dumps(payload), self.runs.timestamp(), run_id, tenant_id)).rowcount == 1
