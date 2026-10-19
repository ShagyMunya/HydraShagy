"""Create initial organizational assessment schema."""
from alembic import op
from app.db import Base
from app import models

revision="0001_program_tables"
down_revision=None
branch_labels=None
depends_on=None

def upgrade(): Base.metadata.create_all(bind=op.get_bind())
def downgrade(): Base.metadata.drop_all(bind=op.get_bind())

