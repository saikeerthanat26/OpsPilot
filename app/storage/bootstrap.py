"""Run additive migrations and initialize checkpoint storage before serving traffic."""
from pathlib import Path
import os
from alembic import command
from alembic.config import Config
from app.platform.enterprise import DurableRunStore
from app.tools.providers import configured_backend


def main():
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "app/storage/migrations"))
    # Match the store's legacy filename setting as well as the new database URL.
    path = os.getenv("OPSPILOT_DATABASE_URL") or os.getenv("OPSPILOT_DB", "/tmp/opspilot.db")
    if "://" not in path: path = "sqlite:///" + str(Path(path).resolve())
    os.environ["OPSPILOT_DATABASE_URL"] = path
    store = DurableRunStore(path)
    # Serialize schema-version changes across replica startup. Checkpoint setup
    # has its own lock and uses a separate connection after this transaction.
    with store.database.engine.begin() as connection:
        if store.database.engine.dialect.name == "postgresql":
            from sqlalchemy import text
            connection.execute(text("SELECT pg_advisory_xact_lock(78460321)"))
        else:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    with store.database.checkpointer(): pass
    configured_backend(store)
    store.database.engine.dispose()


if __name__ == "__main__": main()
