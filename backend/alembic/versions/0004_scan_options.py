"""Add fixed-profile scan options."""
from alembic import op
import sqlalchemy as sa

revision = "0004_scan_options"
down_revision = "0003_tool_runs"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("scan_jobs", sa.Column("options", sa.JSON(), nullable=False, server_default="{}"))

def downgrade():
    op.drop_column("scan_jobs", "options")
