"""Операции с БД для бота и воркера.

Две вещи нужны вертикальному срезу:
  - `create_node_record` — при постановке задачи бот заводит Panel (если её ещё
    нет) и Node в состоянии queued, отдаёт node_id; дальше воркер обновляет эту
    же строку.
  - `record_status` — воркеров `report` пишет сюда: меняет Node.state и
    добавляет строку Task с деталью (история переходов задачи).

Секретов тут нет: токен панели и ключи лежат в Vault, в БД — только путь
(token_vault_path / ssh_key_vault_path). См. db/models.py.

Все функции принимают `session_factory` (async_sessionmaker) параметром, а не
берут глобальную: это шов для тестов (sqlite вместо postgres) и явная граница
владения соединением.
"""
from __future__ import annotations

import logging

import datetime as dt

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from db.models import AuditLog, Node, Panel, User
from db.models import Task as TaskRow

log = logging.getLogger(__name__)

# Длина detail в модели Task — 1024. Режем заранее, чтобы длинная ошибка
# ansible/SDK не уронила вставку.
_DETAIL_MAX = 1024

# Free-лимиты (ADR 0014): без активной подписки — одна нода и один конфиг на
# ноду. Сняты при premium_until в будущем.
FREE_NODE_LIMIT = 1
FREE_CONFIG_PER_NODE_LIMIT = 1


async def upsert_user(
    session_factory: async_sessionmaker, tg_id: int, *, is_admin: bool = False
) -> User:
    """Завести пользователя при первом контакте или вернуть существующего.

    Открытая регистрация (ADR 0014): каждый, кто написал боту, становится
    тенантом с free-тарифом. Повторный вызов не трогает подписку и дату
    создания — только гарантирует наличие строки. is_admin проставляем в True
    лишь для перечисленных в ADMIN_TELEGRAM_IDS (см. вызывающий код); понижать
    существующего админа не будем, чтобы ручное назначение из БД не сбрасывалось.
    """
    async with session_factory() as session:
        user = await session.get(User, tg_id)
        if user is not None:
            if is_admin and not user.is_admin:
                user.is_admin = True
                await session.commit()
            return user
        user = User(tg_id=tg_id, is_admin=is_admin)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def get_user(session_factory: async_sessionmaker, tg_id: int) -> User | None:
    """Пользователь по tg_id, либо None (ещё не регистрировался)."""
    async with session_factory() as session:
        return await session.get(User, tg_id)


def is_premium(user: User | None, *, now: dt.datetime | None = None) -> bool:
    """Активна ли подписка: premium_until в будущем. None/прошлое = free.

    Чистая функция (без БД) — удобно и для проверок в хендлерах, и для тестов.
    now инъектируется для тестов; по умолчанию — UTC-сейчас."""
    if user is None or user.premium_until is None:
        return False
    moment = now or dt.datetime.utcnow()
    return user.premium_until > moment


async def extend_premium(
    session_factory: async_sessionmaker, tg_id: int, days: int
) -> dt.datetime:
    """Продлить подписку на days дней и вернуть новый premium_until.

    Отсчёт от максимума (текущий premium_until, если он в будущем) и «сейчас» —
    чтобы оплата поверх активной подписки не сгорала, а прибавлялась. Вызывается
    из обработчика успешной оплаты (Telegram Stars, ADR 0014)."""
    async with session_factory() as session:
        user = await session.get(User, tg_id)
        if user is None:
            user = User(tg_id=tg_id)
            session.add(user)
        now = dt.datetime.utcnow()
        base = user.premium_until if (user.premium_until and user.premium_until > now) else now
        user.premium_until = base + dt.timedelta(days=days)
        await session.commit()
        return user.premium_until


async def count_owner_nodes(
    session_factory: async_sessionmaker, owner_tg_id: int
) -> int:
    """Сколько нод у владельца (через его панели) — для free-лимита нод."""
    async with session_factory() as session:
        return int(
            await session.scalar(
                select(func.count(Node.id))
                .join(Panel, Node.panel_id == Panel.id)
                .where(Panel.owner_tg_id == owner_tg_id)
            )
            or 0
        )


async def get_or_create_panel(
    session_factory: async_sessionmaker,
    *,
    owner_tg_id: int,
    url: str,
    token_vault_path: str,
) -> int:
    """Вернуть id панели этого владельца по URL, создав её при отсутствии.

    Single-tenant (ADR 0003): один владелец, панель обычно одна. Переиспользуем
    запись по (owner_tg_id, url), чтобы не плодить дубли при добавлении нескольких
    нод к одной панели.
    """
    async with session_factory() as session:
        existing = await session.scalar(
            select(Panel).where(
                Panel.owner_tg_id == owner_tg_id, Panel.url == url
            )
        )
        if existing is not None:
            return existing.id
        panel = Panel(
            owner_tg_id=owner_tg_id, url=url, token_vault_path=token_vault_path
        )
        session.add(panel)
        await session.commit()
        await session.refresh(panel)
        return panel.id


async def get_saved_panel(
    session_factory: async_sessionmaker, owner_tg_id: int
) -> Panel | None:
    """Последняя сохранённая панель владельца, либо None.

    Нужна боту, чтобы не спрашивать URL/токен на каждом /add: single-tenant
    (ADR 0003), панель у владельца обычно одна. Берём самую свежую — на случай,
    если оператор сменил панель через /panel (добавится новая запись с тем же
    owner). Сам токен лежит в Vault по token_vault_path, тут только метаданные.
    """
    async with session_factory() as session:
        return await session.scalar(
            select(Panel)
            .where(Panel.owner_tg_id == owner_tg_id)
            .order_by(Panel.created_at.desc(), Panel.id.desc())
        )


async def create_node_record(
    session_factory: async_sessionmaker,
    *,
    panel_id: int,
    ip: str,
) -> int:
    """Завести Node в состоянии queued и вернуть её id."""
    async with session_factory() as session:
        node = Node(panel_id=panel_id, ip=ip, state="queued")
        session.add(node)
        await session.commit()
        await session.refresh(node)
        return node.id


async def import_panel_node(
    session_factory: async_sessionmaker,
    *,
    panel_id: int,
    remnawave_uuid: str,
    ip: str,
    state: str,
) -> bool:
    """Завести ноду, уже существующую в панели, в локальный список (find-or-create).

    Для кнопки «Синхронизировать»: ноды, заведённые в панели не через бота,
    подтягиваем сюда, чтобы они были видны и отслеживались. Дедупликация по
    (panel_id, remnawave_uuid) — стабильнее, чем по ip, и не плодит дубли при
    повторном синке. Если нода с таким uuid уже есть (импортирована раньше или
    заведена ботом — у ботовой uuid проставляется после регистрации), не трогаем
    её и возвращаем False; новую создаём и возвращаем True.

    SSH-ключа от чужой ноды у нас нет, поэтому ssh_key_vault_path остаётся NULL:
    такая нода частично функциональна (виден статус, но нет действий по SSH).
    """
    async with session_factory() as session:
        existing = await session.scalar(
            select(Node).where(
                Node.panel_id == panel_id,
                Node.remnawave_uuid == remnawave_uuid,
            )
        )
        if existing is not None:
            return False
        node = Node(
            panel_id=panel_id, ip=ip, state=state, remnawave_uuid=remnawave_uuid
        )
        session.add(node)
        await session.commit()
        return True


async def set_node_state_by_uuid(
    session_factory: async_sessionmaker,
    *,
    panel_id: int,
    remnawave_uuid: str,
    state: str,
) -> bool:
    """Обновить Node.state по (panel_id, remnawave_uuid). Вернуть True, если
    статус изменился.

    Для кнопки «Синхронизировать»: список панели уже несёт живой статус каждой
    ноды, поэтому одним проходом освежаем статусы всех уже импортированных нод,
    не опрашивая панель отдельно по каждой. Адресуем по uuid (в синке node_id
    нет). Пишем только при изменении, чтобы не дёргать БД впустую; нет такой
    ноды — молча False."""
    async with session_factory() as session:
        node = await session.scalar(
            select(Node).where(
                Node.panel_id == panel_id,
                Node.remnawave_uuid == remnawave_uuid,
            )
        )
        if node is None or node.state == state:
            return False
        node.state = state
        await session.commit()
        return True


async def set_node_fields(
    session_factory: async_sessionmaker,
    node_id: int,
    *,
    remnawave_uuid: str | None = None,
    ssh_key_vault_path: str | None = None,
) -> None:
    """Проставить ноде её uuid в панели и/или путь SSH-ключа в Vault.

    Вызывается воркером после bootstrap (путь ключа) и после регистрации в
    панели (uuid). Передаём только то, что есть; None-поля не трогаем, чтобы
    повторный вызов не затирал ранее записанное. Нет ноды — просто лог.
    """
    if remnawave_uuid is None and ssh_key_vault_path is None:
        return
    async with session_factory() as session:
        node = await session.get(Node, node_id)
        if node is None:
            log.warning("set_node_fields: нет ноды id=%s", node_id)
            return
        if remnawave_uuid is not None:
            node.remnawave_uuid = remnawave_uuid
        if ssh_key_vault_path is not None:
            node.ssh_key_vault_path = ssh_key_vault_path
        await session.commit()


async def list_panels(session_factory: async_sessionmaker) -> list[Panel]:
    """Все панели — для фонового поллера статуса (ADR 0013).

    Поллер обходит панели, по каждой читает токен из Vault и опрашивает её
    ноды. Single-tenant (ADR 0003), панелей обычно одна-две."""
    async with session_factory() as session:
        rows = await session.scalars(select(Panel))
        return list(rows.all())


async def list_monitored_nodes(
    session_factory: async_sessionmaker, panel_id: int
) -> list[Node]:
    """Ноды панели, зарегистрированные в ней (есть remnawave_uuid).

    Только их и опрашивает поллер: без uuid статус в панели не получить
    (нода ещё в провижине либо его не прошла)."""
    async with session_factory() as session:
        rows = await session.scalars(
            select(Node).where(
                Node.panel_id == panel_id,
                Node.remnawave_uuid.is_not(None),
            )
        )
        return list(rows.all())


async def set_node_state(
    session_factory: async_sessionmaker, node_id: int, state: str
) -> None:
    """Обновить только Node.state, без строки Task в истории.

    Для поллера: он пишет живой статус каждые ~5 минут, и заводить на каждый
    опрос запись Task значило бы засорять аудит ноды. Пишем, только если статус
    изменился, чтобы не дёргать БД впустую. Нет ноды — молча выходим."""
    async with session_factory() as session:
        node = await session.get(Node, node_id)
        if node is None or node.state == state:
            return
        node.state = state
        await session.commit()


async def record_status(
    session_factory: async_sessionmaker,
    node_id: int,
    state: str,
    detail: str,
) -> None:
    """Обновить Node.state и добавить строку Task с деталью перехода.

    Если ноды с таким id нет — просто логируем и выходим: история отдельной
    задачи не должна валить провижининг (FK на отсутствующую ноду не пишем).
    """
    async with session_factory() as session:
        node = await session.get(Node, node_id)
        if node is None:
            log.warning("record_status: нет ноды id=%s (state=%s)", node_id, state)
            return
        node.state = state
        session.add(TaskRow(node_id=node_id, state=state, detail=detail[:_DETAIL_MAX]))
        await session.commit()


async def list_nodes_for_owner(
    session_factory: async_sessionmaker, owner_tg_id: int
) -> list[Node]:
    """Все ноды владельца (через его панели), свежие сверху."""
    async with session_factory() as session:
        rows = await session.scalars(
            select(Node)
            .join(Panel, Node.panel_id == Panel.id)
            .where(Panel.owner_tg_id == owner_tg_id)
            .order_by(Node.created_at.desc(), Node.id.desc())
        )
        return list(rows.all())


async def get_node_for_owner(
    session_factory: async_sessionmaker, node_id: int, owner_tg_id: int
) -> Node | None:
    """Нода по id с проверкой владельца, иначе None."""
    async with session_factory() as session:
        node = await session.get(Node, node_id)
        if node is None:
            return None
        panel = await session.get(Panel, node.panel_id)
        if panel is None or panel.owner_tg_id != owner_tg_id:
            return None
        return node


async def list_node_audit(
    session_factory: async_sessionmaker, node_id: int, owner_tg_id: int
) -> list[dict]:
    """История переходов состояний ноды для владельца.

    Возвращает записи Task (пишутся через record_status) в хронологическом
    порядке. Если нода не принадлежит владельцу — пустой список, не ошибка:
    вызывающий код (веб-слой) сам решает, вернуть 404 или [].
    """
    node = await get_node_for_owner(session_factory, node_id, owner_tg_id)
    if node is None:
        return []
    async with session_factory() as session:
        rows = await session.scalars(
            select(TaskRow)
            .where(TaskRow.node_id == node_id)
            .order_by(TaskRow.id)
        )
        return [
            {"id": t.id, "state": t.state, "detail": t.detail,
             "updated_at": t.updated_at.isoformat() if t.updated_at else None}
            for t in rows.all()
        ]


async def delete_node(
    session_factory: async_sessionmaker, node_id: int, owner_tg_id: int
) -> bool:
    """Убрать ноду из БД деплойера вместе с её историей (Task/AuditLog)."""
    async with session_factory() as session:
        node = await session.get(Node, node_id)
        if node is None:
            return False
        panel = await session.get(Panel, node.panel_id)
        if panel is None or panel.owner_tg_id != owner_tg_id:
            return False
        await session.execute(delete(TaskRow).where(TaskRow.node_id == node_id))
        await session.execute(delete(AuditLog).where(AuditLog.node_id == node_id))
        await session.delete(node)
        await session.commit()
        return True
