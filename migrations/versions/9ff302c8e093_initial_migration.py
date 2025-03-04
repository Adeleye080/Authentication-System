"""
Initial migration

Revision ID: 9ff302c8e093
Revises: 
Create Date: 2025-03-04 12:25:04.548177

"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9ff302c8e093"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    """
    Create Initial User and Auth Database Tables
    """
    # CREATE USER TABLE AND INDEX
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid, primary_key=True),  # use line below for postgres uuid
        # sa.Column("id", sa.UUID, primary_key=True),
        sa.Column("email", sa.String(128), nullable=False, unique=True, index=True),
        sa.Column(
            "recovery_email", sa.String(128), nullable=False, unique=True, index=True
        ),
        sa.Column("password", sa.String(256), nullable=False),
        sa.Column(
            "is_active", sa.Boolean, nullable=False, server_default=sa.text("true")
        ),
        sa.Column(
            "is_verified", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "is_deleted", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at", sa.Boolean, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Index("ix_user_email", "email"),
        sa.Index("ix_user_recovery_email", "recovery_email"),
        sa.Index("ix_user_is_active", "is_active"),
        sa.Index("ix_user_is_verified", "is_verified"),
        sa.Index("ix_user_is_deleted", "is_deleted"),
    )

    # REFRESH TOKEN TABLE AND INDEX
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("user_id", sa.Uuid, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token", sa.String(225), unique=True),
        sa.Column(
            "revoked", sa.Boolean, server_default=sa.text("false"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column(
            "created_at", sa.Boolean, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )


def downgrade():
    op.drop_table("users")
    op.drop_table("refresh_tokens")
