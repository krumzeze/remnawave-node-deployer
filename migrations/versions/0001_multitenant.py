"""multitenant: users table + owner_tg_id -> BigInteger

Revision ID: 0001_multitenant
Revises:
Create Date: 2026-07-01

Первая ревизия проекта. До неё схему создавал только create_all (init_models),
поэтому таблицы panels/nodes/tasks/audit_log на боевой базе уже есть, а users —
нет. Ревизия идемпотентна (проверяет наличие через inspector): заводит users,
если её ещё нет, и переводит panels.owner_tg_id с Integer на BigInteger, если он
ещё не BigInteger. Это делает её безопасной и на свежей базе (где create_all мог
уже всё создать), и на существующей (где нужен только ALTER).
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_multitenant"
down_revision = None
branch_labels = None
depends_on = None


def _has_table(insp, name: str) -> bool:
    return name in insp.get_table_names()


def _column_type(insp, table: str, column: str):
    for col in insp.get_columns(table):
        if col["name"] == column:
            return col["type"]
    return None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # users — новая таблица тенантов. Создаём, только если create_all её ещё не
    # завёл (иначе повторное create_table упало бы).
    if not _has_table(insp, "users"):
        op.create_table(
            "users",
            sa.Column("tg_id", sa.BigInteger(), primary_key=True, autoincrement=False),
            sa.Column("is_admin", sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column("premium_until", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        )

    # panels.owner_tg_id: Integer (int32) не вмещает современные Telegram-ID.
    # Переводим на BigInteger, если он ещё не такой (create_all на существующей
    # базе тип не менял).
    if _has_table(insp, "panels"):
        current = _column_type(insp, "panels", "owner_tg_id")
        if not isinstance(current, sa.BigInteger):
            op.alter_column(
                "panels", "owner_tg_id",
                existing_type=sa.Integer(),
                type_=sa.BigInteger(),
                existing_nullable=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if _has_table(insp, "panels"):
        op.alter_column(
            "panels", "owner_tg_id",
            existing_type=sa.BigInteger(),
            type_=sa.Integer(),
            existing_nullable=False,
        )
    if _has_table(insp, "users"):
        op.drop_table("users")
