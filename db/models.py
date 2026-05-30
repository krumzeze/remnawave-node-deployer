"""Модели БД: panels, nodes, tasks, audit_log.

В БД НИКОГДА не хранятся пароли серверов и токены панелей — только ссылки на
секреты в Vault (vault_path).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import String, Integer, DateTime, ForeignKey, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Panel(Base):
    """Панель Remnawave: своя или подключённая (bring-your-own, ADR 0001)."""
    __tablename__ = "panels"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_tg_id: Mapped[int] = mapped_column(Integer, index=True)
    url: Mapped[str] = mapped_column(String(512))
    token_vault_path: Mapped[str] = mapped_column(String(512))  # секрет — в Vault
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())

    nodes: Mapped[list["Node"]] = relationship(back_populates="panel")


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    panel_id: Mapped[int] = mapped_column(ForeignKey("panels.id"))
    ip: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="queued")
    ssh_key_vault_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    remnawave_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())

    panel: Mapped["Panel"] = relationship(back_populates="nodes")


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"))
    state: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(String(1024), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class AuditLog(Base):
    """Что и когда сделали на сервере — для владельца и разбора инцидентов."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"))
    action: Mapped[str] = mapped_column(String(128))
    auth_method: Mapped[str] = mapped_column(String(16), default="")  # password|key
    detail: Mapped[str] = mapped_column(String(2048), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, server_default=func.now())
