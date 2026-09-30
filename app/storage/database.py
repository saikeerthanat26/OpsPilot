"""Synchronous transactional store for synchronous LangGraph/worker entry points."""
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url

from app.storage.models import metadata


class Connection:
    def __init__(self, engine): self.engine = engine
    def __enter__(self):
        self.conn = self.engine.connect()
        return self
    def __exit__(self, kind, value, traceback):
        try:
            self.conn.rollback() if kind else self.conn.commit()
        finally:
            self.conn.close()
    def execute(self, statement, parameters=()):
        if statement == "BEGIN IMMEDIATE" and self.engine.dialect.name == "postgresql":
            # Serialize short authorization/control transactions across workers.
            # External tool execution never holds this database lock.
            return self.conn.execute(text("SELECT pg_advisory_xact_lock(78460321)"))
        parts = statement.split("?")
        if len(parts) - 1 != len(parameters):
            raise ValueError("SQL parameter count mismatch")
        sql = parts[0] + "".join(f":p{i}" + part for i, part in enumerate(parts[1:]))
        return self.conn.execute(text(sql), {f"p{i}": value for i, value in enumerate(parameters)})


class Database:
    def __init__(self, path):
        if "://" not in path:
            path = "sqlite:///" + str(Path(path).resolve())
        if path.startswith("postgresql://"):
            path = path.replace("postgresql://", "postgresql+psycopg://", 1)
        self.url = make_url(path)
        if self.url.get_backend_name() not in ("sqlite", "postgresql"):
            raise ValueError("only SQLite and PostgreSQL are supported")
        kwargs = {"pool_pre_ping": True}
        if self.url.get_backend_name() == "sqlite":
            kwargs["connect_args"] = {"timeout": 15, "check_same_thread": False}
        self.engine = create_engine(self.url, **kwargs)
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine, "connect")
            def configure(connection, _):
                connection.execute("PRAGMA busy_timeout=15000")
                connection.execute("PRAGMA journal_mode=WAL")
        with self.engine.begin() as conn:
            if self.engine.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_xact_lock(78460321)"))
            else:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            metadata.create_all(conn)

    def connect(self): return Connection(self.engine)

    @contextmanager
    def checkpointer(self):
        if self.engine.dialect.name == "postgresql":
            from langgraph.checkpoint.postgres import PostgresSaver
            uri = self.url.set(drivername="postgresql").render_as_string(hide_password=False)
            with PostgresSaver.from_conn_string(uri) as saver:
                saver.conn.execute("SELECT pg_advisory_lock(78460322)")
                try: saver.setup()
                finally: saver.conn.execute("SELECT pg_advisory_unlock(78460322)")
                yield saver
        else:
            from langgraph.checkpoint.sqlite import SqliteSaver
            with SqliteSaver.from_conn_string(self.url.database) as saver:
                saver.setup()
                yield saver
