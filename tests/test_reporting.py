"""Тесты реального report на фейковых швах persist/notify.

Проверяем, что report пишет статус и шлёт сообщение, что сбой одного шва не
ломает другой и не пробрасывает исключение (отчёт не должен валить провижининг),
и что без chat_id уведомление не отправляется.
"""
from __future__ import annotations

import pytest

from orchestrator import reporting
from orchestrator.statemachine import NodeState


@pytest.mark.asyncio
async def test_persists_and_notifies():
    persisted: list[tuple] = []
    notified: list[tuple] = []

    async def persist(node_id, state, detail):
        persisted.append((node_id, state, detail))

    async def notify(chat_id, text):
        notified.append((chat_id, text))

    report = reporting.make_reporter(7, 100, persist=persist, notify=notify)
    await report(NodeState.ONLINE, "Нода online")

    assert persisted == [(7, "online", "Нода online")]
    assert notified[0][0] == 100
    assert "нода онлайн" in notified[0][1].lower()


@pytest.mark.asyncio
async def test_no_notify_without_chat_id():
    notified = []

    async def notify(chat_id, text):
        notified.append(text)

    report = reporting.make_reporter(7, None, notify=notify)
    await report(NodeState.QUEUED, "")

    assert notified == []


@pytest.mark.asyncio
async def test_notify_failure_does_not_break_persist():
    persisted = []

    async def persist(node_id, state, detail):
        persisted.append(state)

    async def bad_notify(chat_id, text):
        raise RuntimeError("telegram down")

    report = reporting.make_reporter(7, 100, persist=persist, notify=bad_notify)
    # Не должно бросить наружу.
    await report(NodeState.FAILED, "что-то сломалось")

    assert persisted == ["failed"]


@pytest.mark.asyncio
async def test_persist_failure_is_swallowed():
    async def bad_persist(node_id, state, detail):
        raise RuntimeError("db down")

    report = reporting.make_reporter(7, None, persist=bad_persist)
    await report(NodeState.PROVISIONING, "x")  # не бросает


def test_format_status_combines_title_and_detail():
    text = reporting.format_status(NodeState.BOOTSTRAPPING, "Подключаюсь к 1.2.3.4")
    assert text.startswith("Подключаюсь к серверу")
    assert "1.2.3.4" in text
    # Пустая деталь — только заголовок, без лишних переводов строки.
    assert reporting.format_status(NodeState.ONLINE, "") == "Готово: нода онлайн"
