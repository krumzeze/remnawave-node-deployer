"""Тесты барьера доступа: белый список владельцев бота.

Проверяем чистую функцию решения и поведение middleware на фейковых апдейтах,
без поднятия Telegram. В списке → пропуск; не в списке → отказ; пустой список →
бот ненастроен.
"""
from __future__ import annotations

import pytest

from bot import access
from bot.access import AccessDecision, WhitelistMiddleware, access_decision


def test_access_decision_allow_when_in_list():
    assert access_decision(111, {111, 222}) is AccessDecision.ALLOW


def test_access_decision_forbidden_when_not_in_list():
    assert access_decision(333, {111, 222}) is AccessDecision.FORBIDDEN


def test_access_decision_not_configured_when_empty():
    # Пустой список = бот ненастроен, не пускаем даже знакомый id.
    assert access_decision(111, set()) is AccessDecision.NOT_CONFIGURED


def test_access_decision_forbidden_without_user_id():
    # Апдейт без отправителя при заданном списке — отказ.
    assert access_decision(None, {111}) is AccessDecision.FORBIDDEN


class _FakeUser:
    def __init__(self, uid):
        self.id = uid


class _FakeMessage:
    """Минимальный апдейт с from_user и answer, как у aiogram Message."""

    def __init__(self, uid):
        self.from_user = _FakeUser(uid) if uid is not None else None
        self.answers = []

    async def answer(self, text, **kwargs):
        self.answers.append(text)


@pytest.mark.asyncio
async def test_middleware_passes_allowed_user():
    mw = WhitelistMiddleware(lambda: {111})
    event = _FakeMessage(111)
    called = []

    async def handler(ev, data):
        called.append(ev)
        return "handled"

    result = await mw(handler, event, {})

    assert result == "handled"
    assert called == [event]
    assert event.answers == []


@pytest.mark.asyncio
async def test_middleware_blocks_foreign_user():
    mw = WhitelistMiddleware(lambda: {111})
    event = _FakeMessage(999)
    called = []

    async def handler(ev, data):
        called.append(ev)

    result = await mw(handler, event, {})

    assert result is None
    assert called == []                     # хендлер не вызван
    assert event.answers == [access.FORBIDDEN_TEXT]


@pytest.mark.asyncio
async def test_middleware_reports_not_configured_when_empty_list():
    mw = WhitelistMiddleware(lambda: set())
    event = _FakeMessage(111)
    called = []

    async def handler(ev, data):
        called.append(ev)

    result = await mw(handler, event, {})

    assert result is None
    assert called == []
    assert event.answers == [access.NOT_CONFIGURED_TEXT]
