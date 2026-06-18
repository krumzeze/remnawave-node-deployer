"""Фоновый мониторинг статуса нод (ADR 0013).

arq-cron раз в ~5 минут обходит ноды с remnawave_uuid, тянет живой статус из
панели и пишет его в Node.state. Это чинит «протухший» список «Мои ноды»:
раньше статус обновлялся только кнопкой на экране одной ноды и в БД не
сохранялся, а импортированные синком ноды навсегда застывали в статусе на
момент синка.

При устойчивом уходе ноды в offline шлём владельцу алерт. Чтобы моргание при
ребуте VPS не порождало ложную тревогу, алерт срабатывает только после
OFFLINE_ALERT_THRESHOLD подряд опросов offline (~15 минут реальной
недоступности при шаге 5 минут). Когда нода возвращается, шлём короткое
«снова online». Счётчики живут в ctx воркера между запусками cron; перезапуск
воркера их сбрасывает — это лишь отложит, но не потеряет алерт.

Как и tasks.py, основной цикл собран на инъектируемых швах (фабрика клиента,
доступ к Vault/БД, отправка в Telegram) — так он проверяется без живой панели,
БД и бота.
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable

from orchestrator.remnawave_client import NodeConnState, RemnawaveClient

logger = logging.getLogger(__name__)

# Шаг опроса в минутах и порог алерта по подряд идущим offline.
POLL_EVERY_MINUTES = 5
OFFLINE_ALERT_THRESHOLD = 3


def _default_make_client(url: str, token: str) -> RemnawaveClient:
    return RemnawaveClient(url, token)


async def run_status_poll(
    *,
    session_factory,
    vault_get: Callable[[str], dict],
    make_client: Callable[[str, str], RemnawaveClient] = _default_make_client,
    notify: Callable[[int, str], Awaitable[None]] | None,
    counts: dict[int, int],
    alerted: set[int],
) -> None:
    """Один проход поллера: обновить статус всех нод и разослать алерты.

    counts/alerted — переживающее запуски состояние (живёт в ctx воркера):
    counts[node_id] — сколько опросов подряд нода была offline; alerted —
    ноды, по которым алерт уже отправлен (чтобы не слать его повторно каждые
    5 минут, пока нода лежит).
    """
    from db.repo import list_monitored_nodes, list_panels, set_node_state

    panels = await list_panels(session_factory)
    for panel in panels:
        try:
            token = (vault_get(panel.token_vault_path) or {}).get("token", "")
        except Exception:  # noqa: BLE001 — нет токена/Vault недоступен → пропускаем панель
            logger.warning("poll: не прочитать токен панели id=%s", panel.id)
            continue
        if not token:
            continue
        client = make_client(panel.url, token)

        nodes = await list_monitored_nodes(session_factory, panel.id)
        for node in nodes:
            await _poll_one(
                client=client,
                session_factory=session_factory,
                set_node_state=set_node_state,
                notify=notify,
                owner_tg_id=panel.owner_tg_id,
                node=node,
                counts=counts,
                alerted=alerted,
            )


async def _poll_one(
    *,
    client: RemnawaveClient,
    session_factory,
    set_node_state,
    notify: Callable[[int, str], Awaitable[None]] | None,
    owner_tg_id: int,
    node,
    counts: dict[int, int],
    alerted: set[int],
) -> None:
    """Опросить одну ноду: записать статус и при необходимости поднять алерт.

    Любой сбой запроса к панели по одной ноде не должен ронять весь проход —
    логируем и идём дальше (поллер фоновый, его задача — не падать)."""
    try:
        status = await client.get_node_status(node.remnawave_uuid)
    except Exception:  # noqa: BLE001 — сбой по одной ноде не валит весь обход
        logger.warning("poll: не получить статус ноды id=%s", node.id)
        return

    await set_node_state(session_factory, node.id, status.value)

    if status is NodeConnState.OFFLINE:
        counts[node.id] = counts.get(node.id, 0) + 1
        if counts[node.id] >= OFFLINE_ALERT_THRESHOLD and node.id not in alerted:
            alerted.add(node.id)
            await _send(
                notify, owner_tg_id,
                f"🔴 Нода {node.ip} не отвечает "
                f"(offline уже ~{counts[node.id] * POLL_EVERY_MINUTES} мин).",
            )
        return

    # Не offline: сбрасываем счётчик и, если по ноде был алерт, сообщаем о возврате.
    counts[node.id] = 0
    if node.id in alerted:
        alerted.discard(node.id)
        if status is NodeConnState.ONLINE:
            await _send(notify, owner_tg_id, f"🟢 Нода {node.ip} снова online.")


async def _send(
    notify: Callable[[int, str], Awaitable[None]] | None, chat_id: int, text: str
) -> None:
    """Доставить алерт владельцу. Сбой Telegram не должен ронять проход."""
    if notify is None:
        return
    try:
        await notify(chat_id, text)
    except Exception:  # noqa: BLE001 — сбой доставки не критичен для мониторинга
        logger.exception("poll: не отправить алерт в чат %s", chat_id)


async def poll_node_statuses(ctx: dict) -> None:
    """arq-cron вход: собрать боевые швы из ctx воркера и сделать один проход.

    Состояние счётчиков/алертов держим в самом ctx — он переживает запуски
    cron в пределах жизни воркера. Бот и его отправка берутся из ctx (его кладёт
    _worker_startup), фабрика сессий и Vault — боевые.
    """
    from db import get_sessionmaker
    from secretstore.vault import VaultStore

    counts = ctx.setdefault("poll_offline_counts", {})
    alerted = ctx.setdefault("poll_alerted", set())

    bot = ctx.get("bot")
    notify = None
    if bot is not None:
        async def notify(cid: int, text: str) -> None:  # noqa: F811
            await bot.send_message(cid, text)

    await run_status_poll(
        session_factory=get_sessionmaker(),
        vault_get=VaultStore().get,
        notify=notify,
        counts=counts,
        alerted=alerted,
    )
