import os
from alembic import context
from sqlalchemy import create_engine
from app.storage.models import metadata

url = os.getenv("OPSPILOT_DATABASE_URL", "sqlite:////tmp/opspilot.db")
url = url.replace("postgresql://", "postgresql+psycopg://", 1)


def migrate(connection):
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction(): context.run_migrations()


if context.is_offline_mode():
    context.configure(url=url, target_metadata=metadata, literal_binds=True)
    with context.begin_transaction(): context.run_migrations()
elif context.config.attributes.get("connection") is not None:
    migrate(context.config.attributes["connection"])
else:
    with create_engine(url).connect() as connection: migrate(connection)
