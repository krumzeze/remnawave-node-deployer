"""Реальный `report` для конвейера: запись статуса в БД + сообщение в Telegram.

В tasks.py `report` — инъектируемый шов `(NodeState, str) -> awaitable`. По
умолчанию там заглушка-лог; здесь собирается боевая реализация. Она привязана к
конкретной задаче (node_id, chat_id оператора), поэтому строится фабрикой на
каждую задачу, а не живёт статической зависимостью.

Два действия делаются через инъекцию (`persist`, `notify`) — это и шов для
тестов, и развязка: воркер не знает ни про SQLAlchemy, ни про aiogram напрямую.
Оба вызова изолированы: сбой доставки в Telegram или записи в БД логируется, но
не превращается в исключение — иначе ошибка отчёта уронила бы сам провижининг
(а его шаги необратимы и важнее, чем доставка статуса).
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable

from orchestrator.statemachine import NodeState

log = logging.getLogger(__name__)

# Человекочитаемый заголовок на каждое состояние — это видит оператор в чате.
_TITLES: dict[NodeState, str] = {
    NodeState.QUEUED: "В очереди",
    NodeState.BOOTSTRAPPING: "Подключаюсь к серверу",
    NodeState.PROVISIONING: "Настраиваю сервер",
    NodeState.REGISTERING: "Регистрирую ноду в панели",
    NodeState.ONLINE: "Готово: нода онлайн",
    NodeState.FAILED: "Ошибка",
    NodeState.ROLLED_BACK: "Откат выполнен",
}

# Тип швов.
PersistFn = Callable[[int, str, str], Awaitable[None]]   # (node_id, state, detail)
NotifyFn = Callable[[int, str], Awaitable[None]]          # (chat_id, text)


def format_status(state: NodeState, detail: str) -> str:
    """Собрать текст сообщения оператору: заголовок состояния + деталь."""
    title = _TITLES.get(state, state.value)
    detail = (detail or "").strip()
    if not detail or detail == title:
        return title
    return f"{title}\n{detail}"


def make_reporter(
    node_id: int,
    chat_id: int | None,
    *,
    persist: PersistFn | None = None,
    notify: NotifyFn | None = None,
) -> Callable[[NodeState, str], Awaitable[None]]:
    """Собрать `report`, привязанный к задаче.

    persist(node_id, state, detail) — запись в БД (Node.state + Task);
    notify(chat_id, text) — доставка в Telegram. Любой из них можно не задавать
    (например, в задаче без chat_id notify опускается).
    """

    async def report(state: NodeState, detail: str) -> None:
        if persist is not None:
            try:
                await persist(node_id, state.value, detail)
            except Exception:  # noqa: BLE001 — сбой записи не должен валить задачу
                log.exception("report: не удалось записать статус ноды id=%s", node_id)

        if notify is not None and chat_id is not None:
            try:
                await notify(chat_id, format_status(state, detail))
            except Exception:  # noqa: BLE001 — сбой Telegram не должен валить задачу
                log.exception("report: не удалось отправить статус в чат %s", chat_id)

    return report
