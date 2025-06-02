"""
Combined final migration - represents the complete schema state

Revision ID: combined_final_schema
Revises:
Create Date: 2025-05-30 12:00:00.000000

"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from api.v1.schemas.user import LoginSource

# revision identifiers, used by Alembic.
revision: str = "combined_final_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    """
    Create complete database schema with all final tables and relationships
    """

    # Define enum types for different databases
    audit_log_event_enum = sa.Enum(
        "LOGIN",
        "PASSWORD_CHANGE",
        "PASSWORD_RESET",
        "CREATE_ACCOUNT",
        "REQUEST_VERIFICATION",
        "UPDATE_ACCOUNT",
        "REQUEST_MAGIC_LINK",
        "MAIL_ERROR",
        "DELETE_USER",
        "DELETE_SELF",
        "HARD_DELETE",
        "VERIFY_EMAIL",
        name="auditlogeventenum",
    )

    login_source_enum = sa.Enum(
        "PASSWORD", "GOOGLE", "MAGICLINK", "FACEBOOK", "GITHUB", name="loginsource"
    )

    # CREATE USERS TABLE
    op.create_table(
        "auth_users",
        sa.Column("id", sa.String(36), primary_key=True, index=True),
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
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Column(
            "login_initiated",
            sa.Boolean,
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "is_superadmin",
            sa.Boolean,
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "is_moderator",
            sa.Boolean,
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "is_banned",
            sa.Boolean,
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("secondary_role", sa.String(128), nullable=True),
        sa.Column("last_login", sa.DateTime, nullable=True),
        sa.Column("login_source", login_source_enum, nullable=True),
        # Indexes
        sa.Index("ix_user_email", "email"),
        sa.Index("ix_user_recovery_email", "recovery_email"),
        sa.Index("ix_user_is_active", "is_active"),
        sa.Index("ix_user_is_verified", "is_verified"),
        sa.Index("ix_user_is_deleted", "is_deleted"),
        sa.Index("ix_user_last_login", "last_login"),
        sa.Index("ix_user_login_initiated", "login_initiated"),
        sa.Index("ix_user_login_source", "login_source"),
        sa.Index("ix_user_secondary_role", "secondary_role"),
    )

    # CREATE REFRESH TOKENS TABLE
    op.create_table(
        "auth_refresh_tokens",
        sa.Column("id", sa.String(36), primary_key=True, index=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("auth_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token", sa.String(400), unique=True, nullable=False),
        sa.Column(
            "revoked", sa.Boolean, server_default=sa.text("false"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column(
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Index("ix_refresh_token_owner", "user_id"),
        sa.Index("ix_refresh_token", "token"),
        sa.Index("ix_refresh_token_is_revoked", "revoked"),
        sa.Index("ix_refresh_token_expire_at", "expires_at"),
    )

    # CREATE AUDIT LOGS TABLE
    op.create_table(
        "auth_audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("event", audit_log_event_enum, nullable=False),
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
        # Indexes
        sa.Index("ix_audit_log_user_id", "user_id"),
        sa.Index("ix_audit_log_event", "event"),
        sa.Index("ix_audit_log_status", "status"),
        sa.Index("ix_audit_log_timestamp", "timestamp"),
        sa.Index("ix_audit_log_user_ip_address", "ip_address"),
    )

    # CREATE USER DEVICES TABLE (Final schema)
    op.create_table(
        "auth_user_devices",
        sa.Column("id", sa.String(36), primary_key=True, index=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("auth_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_name", sa.String(60), index=True),
        sa.Column("user_agent_string", sa.String(500), nullable=False),
        sa.Column("os_name", sa.String(50), nullable=True),
        sa.Column("os_version", sa.String(50), nullable=True),
        sa.Column("is_mobile", sa.Boolean(), nullable=False),
        sa.Column("is_tablet", sa.Boolean(), nullable=False),
        sa.Column("is_pc", sa.Boolean(), nullable=False),
        sa.Column("is_bot", sa.Boolean(), nullable=False),
        sa.Column("device_fingerprint", sa.String(64), nullable=False),
        sa.Column(
            "last_used",
            sa.DateTime(timezone=True),
            default=sa.func.now(),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        # Indexes and constraints
        sa.Index("ix_auth_user_devices_user_id", "user_id"),
        sa.Index("ix_auth_user_devices_user_agent_string", "user_agent_string"),
        sa.Index("ix_auth_user_devices_device_fingerprint", "device_fingerprint"),
        sa.Index("ix_auth_user_devices_os_name", "os_name"),
        sa.Index("ix_auth_user_devices_os_version", "os_version"),
        sa.UniqueConstraint(
            "user_id", "device_fingerprint", name="unique_user_device_fingerprint"
        ),
    )

    # CREATE MMDB TRACKER TABLE
    op.create_table(
        "auth_mmdb_tracker",
        sa.Column(
            "id",
            sa.String(36) if op.get_context().dialect.name == "mysql" else PG_UUID,
            primary_key=True,
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
    )

    # CREATE COUNTRY BLACKLISTS TABLE (Referenced in migrations)
    op.create_table(
        "auth_country_blacklists",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("country_name", sa.String(128), nullable=False),
        sa.Column(
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.UniqueConstraint("country_code"),
        sa.Index("ix_blacklisted_country_code", "country_code"),
        sa.Index("ix_blacklisted_country_name", "country_name"),
        sa.Index("ix_blacklisted_country_reason_for_being_blacklisted", "reason"),
    )

    # CREATE COUNTRY BLACKLIST HISTORY TABLE (Referenced in migrations)
    op.create_table(
        "auth_country_blacklist_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("country_name", sa.String(128), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("reason", sa.String(256), nullable=True),
        sa.Column("changed_by", sa.String(128), nullable=True),
        sa.Column(
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Column(
            "timestamp",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    # CREATE TOTP DEVICES TABLE (Referenced in migrations)
    op.create_table(
        "auth_totp_devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("auth_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("secret", sa.LargeBinary(128), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False, default=False, index=True),
        sa.Column("name", sa.String(100), nullable=True),
        sa.Column("last_used", sa.DateTime, nullable=True, index=True),
        sa.Column(
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.UniqueConstraint("user_id"),
        sa.Index("ix_auth_totp_devices_confirmed", "confirmed"),
    )

    # CREATE USER ATTRIBUTES TABLE (Referenced in migrations)
    op.create_table(
        "auth_user_attributes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("auth_users.id"),
            nullable=False,
        ),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("value", sa.String(256), nullable=True),
        sa.Column(
            "created_at", sa.DateTime, nullable=True, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=True,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Index("ix_auth_user_attributes_id", "id"),
    )


def downgrade():
    """
    Drop all tables in reverse dependency order
    """
    # Drop tables in reverse order of dependencies
    op.drop_table("auth_user_attributes")
    op.drop_table("auth_totp_devices")
    op.drop_table("auth_country_blacklist_history")
    op.drop_table("auth_country_blacklists")
    op.drop_table("auth_mmdb_tracker")
    op.drop_table("auth_user_devices")
    op.drop_table("auth_audit_logs")
    op.drop_table("auth_refresh_tokens")
    op.drop_table("auth_users")

    # Drop enum types for PostgreSQL
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS auditlogeventenum")
        op.execute("DROP TYPE IF EXISTS loginsource")
