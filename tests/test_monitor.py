"""Тесты фонового поллера статуса нод (orchestrator/monitor.py, ADR 0013).

Проверяем на реальном sqlite + фейковом клиенте панели: поллер пишет живой
статус в Node.state, поднимает алерт только после порога подряд идущих offline
и шлёт «снова online» при возврате. Фейки те же по духу, что и в test_tasks:
клиент с заранее заданным статусом, notify собирает отправленные сообщения.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from db import repo
from db.models import Base, Node
from orchestrator import monitor
from orchestrator.remnawave_client import NodeConnState


@pytest_asyncio.fixture
async def sm():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


class FakeClient:
    """Клиент панели, отдающий заранее заданный статус по uuid."""

    def __init__(self, status: NodeConnState) -> None:
        self.status = status

    async def get_node_status(self, uuid: str) -> NodeConnState:
        return self.status


def _poller(status: NodeConnState, sent: list, counts=None, alerted=None):
    """Собрать аргументы run_status_poll вокруг фейков с одним статусом."""

    async def notify(chat_id: int, text: str) -> None:
        sent.append((chat_id, text))

    return dict(
        vault_get=lambda path: {"token": "tok"},
        make_client=lambda url, token: FakeClient(status),
        notify=notify,
        counts=counts if counts is not None else {},
        alerted=alerted if alerted is not None else set(),
    )


async def _seed_node(sm, *, owner=1, ip="1.2.3.4", uuid="rw-1", state="online"):
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=owner, url="https://p", token_vault_path="panels/1/token"
    )
    nid = await repo.create_node_record(sm, panel_id=panel_id, ip=ip)
    await repo.set_node_fields(sm, nid, remnawave_uuid=uuid)
    if state != "queued":
        await repo.set_node_state(sm, nid, state)
    return nid


@pytest.mark.asyncio
async def test_poll_writes_live_status_to_db(sm):
    nid = await _seed_node(sm, state="online")
    sent: list = []
    await monitor.run_status_poll(
        session_factory=sm, **_poller(NodeConnState.OFFLINE, sent)
    )
    async with sm() as session:
        node = await session.get(Node, nid)
        assert node.state == "offline"


@pytest.mark.asyncio
async def test_node_without_uuid_is_skipped(sm):
    # Нода без remnawave_uuid в опрос не попадает (статус в панели не получить).
    panel_id = await repo.get_or_create_panel(
        sm, owner_tg_id=1, url="https://p", token_vault_path="panels/1/token"
    )
    nid = await repo.create_node_record(sm, panel_id=panel_id, ip="9.9.9.9")
    sent: list = []
    await monitor.run_status_poll(
        session_factory=sm, **_poller(NodeConnState.OFFLINE, sent)
    )
    async with sm() as session:
        node = await session.get(Node, nid)
        assert node.state == "queued"  # не тронули


@pytest.mark.asyncio
async def test_alert_only_after_threshold(sm):
    await _seed_node(sm, state="online")
    sent: list = []
    counts: dict = {}
    alerted: set = set()
    args = _poller(NodeConnState.OFFLINE, sent, counts=counts, alerted=alerted)

    # Порог — OFFLINE_ALERT_THRESHOLD подряд. До него молчим.
    for _ in range(monitor.OFFLINE_ALERT_THRESHOLD - 1):
        await monitor.run_status_poll(session_factory=sm, **args)
    assert sent == []

    # На пороговом проходе — ровно один алерт.
    await monitor.run_status_poll(session_factory=sm, **args)
    assert len(sent) == 1
    assert "не отвечает" in sent[0][1]

    # Дальше нода всё ещё offline — повторно не спамим.
    await monitor.run_status_poll(session_factory=sm, **args)
    assert len(sent) == 1


@pytest.mark.asyncio
async def test_connecting_also_triggers_alert(sm):
    # Упавшая нода часто висит в connecting (вечный реконнект), а не в offline.
    # Это тоже недоступность — алерт должен сработать после порога.
    await _seed_node(sm, state="online")
    sent: list = []
    counts: dict = {}
    alerted: set = set()
    args = _poller(NodeConnState.CONNECTING, sent, counts=counts, alerted=alerted)

    for _ in range(monitor.OFFLINE_ALERT_THRESHOLD):
        await monitor.run_status_poll(session_factory=sm, **args)
    assert len(sent) == 1
    assert "не отвечает" in sent[0][1]


@pytest.mark.asyncio
async def test_disabled_does_not_trigger_alert(sm):
    # Выключенную оператором ноду (disabled) за недоступность не считаем.
    await _seed_node(sm, state="online")
    sent: list = []
    counts: dict = {}
    alerted: set = set()
    args = _poller(NodeConnState.DISABLED, sent, counts=counts, alerted=alerted)

    for _ in range(monitor.OFFLINE_ALERT_THRESHOLD + 1):
        await monitor.run_status_poll(session_factory=sm, **args)
    assert sent == []


@pytest.mark.asyncio
async def test_recovery_message_after_alert(sm):
    nid = await _seed_node(sm, state="online")
    sent: list = []
    counts = {nid: monitor.OFFLINE_ALERT_THRESHOLD}  # уже за порогом
    alerted = {nid}  # алерт уже отправлен ранее

    await monitor.run_status_poll(
        session_factory=sm,
        **_poller(NodeConnState.ONLINE, sent, counts=counts, alerted=alerted),
    )
    assert len(sent) == 1
    assert "снова online" in sent[0][1]
    assert nid not in alerted
    assert counts[nid] == 0
