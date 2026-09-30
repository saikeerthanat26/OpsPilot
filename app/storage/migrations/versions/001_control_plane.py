"""Additive baseline for V0.5 databases and new PostgreSQL deployments."""
from alembic import op
from app.storage.models import metadata
revision = "001_control_plane"
down_revision = None
branch_labels = None
depends_on = None


def upgrade(): metadata.create_all(op.get_bind(), checkfirst=True)


def downgrade():
    # Rollback must not silently destroy operational state.
    raise RuntimeError("export and explicitly archive control-plane state before schema removal")
