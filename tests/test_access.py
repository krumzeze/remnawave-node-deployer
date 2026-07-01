"""Тесты регистрации пользователей (открытый доступ, ADR 0014).

Проверяем middleware на фейковых апдейтах без Telegram и БД: отправитель
регистрируется и кладётся в data['user']; админ помечается по списку; апдейт
без from_user проходит как есть; сбой upsert не роняет апдейт.
"""
from __future__ import annotations

import pytest

from bot.access import RegistrationMiddleware


class _FakeUser:
    def __init__(self, uid):
        self.id = uid


class _FakeMessage:
    def __init__(self, uid):
        self.from_user = _FakeUser(uid) if uid is not None else None


def _mw(admins=frozenset(), *, fail=False):
    seen = []

    async def upsert(tg_id, is_admin):
        if fail:
            raise RuntimeError("db down")
        seen.append((tg_id, is_admin))
        return {"tg_id": tg_id, "is_admin": is_admin}

    mw = RegistrationMiddleware(upsert, lambda: set(admins))
    return mw, seen


@pytest.mark.asyncio
async def test_registers_sender_and_injects_user():
    mw, seen = _mw()
    event = _FakeMessage(111)
    data = {}

    async def handler(ev, d):
        return "handled"

    result = await mw(handler, event, data)

    assert result == "handled"
    assert seen == [(111, False)]
    assert data["user"] == {"tg_id": 111, "is_admin": False}


@pytest.mark.asyncio
async def test_marks_admin_from_list():
    mw, seen = _mw(admins={111})
    event = _FakeMessage(111)
    data = {}

    async def handler(ev, d):
        return None

    await mw(handler, event, data)

    assert seen == [(111, True)]
    assert data["user"]["is_admin"] is True


@pytest.mark.asyncio
async def test_passes_through_without_sender():
    mw, seen = _mw()
    event = _FakeMessage(None)
    called = []

    async def handler(ev, d):
        called.append(ev)
        return "ok"

    result = await mw(handler, event, {})

    assert result == "ok"
    assert called == [event]
    assert seen == []                      # регистрировать некого


@pytest.mark.asyncio
async def test_upsert_failure_does_not_break_update():
    mw, _ = _mw(fail=True)
    event = _FakeMessage(111)
    data = {}
    called = []

    async def handler(ev, d):
        called.append(ev)
        return "handled"

    result = await mw(handler, event, data)

    assert result == "handled"             # апдейт всё равно доходит до хендлера
    assert called == [event]
    assert "user" not in data              # но пользователь не проброшен
