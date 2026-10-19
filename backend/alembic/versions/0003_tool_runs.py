"""Add safe non-executable tool registry runs."""
from alembic import op
import sqlalchemy as sa

revision = "0003_tool_runs"
down_revision = "0002_evidence_tool_analysis"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("tool_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.String(length=120), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("tool_id", sa.String(length=80), nullable=False),
        sa.Column("profile_id", sa.String(length=120), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("result_location", sa.String(length=500), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["assessment_id"],["assessments.id"],ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"],["assets.id"],ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_tool_runs_org","tool_runs",["organization_id"])
    op.create_index("ix_tool_runs_assessment","tool_runs",["assessment_id"])
    op.create_index("ix_tool_runs_asset","tool_runs",["asset_id"])

def downgrade():
    op.drop_table("tool_runs")
