"""Add source and parsed review data to encrypted evidence records."""
from alembic import op
import sqlalchemy as sa

revision = "0002_evidence_tool_analysis"
down_revision = "0001_program_tables"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("evidence", sa.Column("source_tool", sa.String(length=40), nullable=False, server_default="manual"))
    op.add_column("evidence", sa.Column("analysis", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))

def downgrade():
    op.drop_column("evidence", "analysis")
    op.drop_column("evidence", "source_tool")
