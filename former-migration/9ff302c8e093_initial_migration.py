"""
Initial migration

Revision ID: 9ff302c8e093
Revises:
Create Date: 2025-03-04 12:25:04.548177

"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

from api.v1.schemas.user import RoleEnum, LoginSource


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
        sa.Column("id", sa.String(36), primary_key=True, index=True),
        # use line below for postgres uuid
        # sa.Column("id", sa.UUID, primary_key=True),
        sa.Column("username", sa.String(128), nullable=False, unique=True),
        sa.Column("email", sa.String(128), nullable=False, unique=True),
        sa.Column("recovery_email", sa.String(128), nullable=True, unique=True),
        sa.Column("password", sa.String(256), nullable=False),
        sa.Column(
            "is_active", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "is_verified", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "is_deleted", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Column(
            "role", sa.Enum(RoleEnum), server_default=RoleEnum.USER, nullable=False
        ),
        sa.Column(
            "login_initiated",
            sa.Boolean,
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("last_login", sa.DateTime, nullable=True),
        sa.Column("login_source", sa.Enum(LoginSource), nullable=True),
        sa.Index("ix_user_username", "username"),
        sa.Index("ix_user_email", "email"),
        sa.Index("ix_user_recovery_email", "recovery_email"),
        sa.Index("ix_user_role", "role"),
        sa.Index("ix_user_is_active", "is_active"),
        sa.Index("ix_user_is_verified", "is_verified"),
        sa.Index("ix_user_is_deleted", "is_deleted"),
        sa.Index("ix_user_last_login", "last_login"),
        sa.Index("ix_user_login_source", "login_source"),
    )

    # REFRESH TOKEN TABLE AND INDEX
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(36), primary_key=True, index=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token", sa.String(400), unique=True),
        sa.Column(
            "revoked", sa.Boolean, server_default=sa.text("false"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column(
            "created_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Index("ix_refresh_token_owner", "user_id"),
        sa.Index("ix_refresh_token", "token"),
        sa.Index("ix_refresh_token_is_revoked", "revoked"),
        sa.Index("ix_refresh_token_expire_at", "expires_at"),
    )

    # CREATE AUDIT LOG TABLE AND INDEX
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            nullable=False,
        ),
        sa.Column("event", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column("ip_address", sa.String(50), nullable=True),
        sa.Column("user_agent", sa.Text(300), nullable=True),
        sa.Index("ix_audit_log_id", "id"),
        sa.Index("ix_audit_log_user_id", "user_id"),
        sa.Index("ix_audit_log_event", "event"),
        sa.Index("ix_audit_log_status", "status"),
        sa.Index("ix_audit_log_timestamp", "timestamp"),
        sa.Index("ix_audit_log_user_ip_address", "ip_address"),
    )

    # CREATE DEVICE TABLE AND INDEX

    op.create_table(
        "user_devices",
        sa.Column("id", sa.String(36), primary_key=True, index=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_name", sa.String(60), index=True),
        sa.Column("ip_address", sa.String(30), nullable=False, index=True),
        sa.Column("user_agent", sa.String(128)),
        sa.Column(
            "last_used",
            sa.DateTime(timezone=True),
            default=sa.func.now(),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "created_at", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Index("ix_device_user_id", "user_id"),
        sa.Index("ix_device_ip_address", "ip_address"),
        sa.Index("ix_device_last_used", "last_used"),
    )


def downgrade():
    # Drop the refresh_tokens table
    op.drop_table("refresh_tokens")

    # Drop the enum type (only needed for PostgreSQL)
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS roleenum")

    # Drop the audit_logs table
    op.drop_table("audit_logs")

    # Drop the user_devices table
    op.drop_table("user_devices")

    # Drop the users table
    op.drop_table("users")
