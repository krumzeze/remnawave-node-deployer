"""Хендлеры бота: меню, список нод, панель и мастер добавления — на кнопках.

Управление построено на inline-кнопках (aiogram CallbackData, см.
bot/callbacks.py и bot/keyboards.py), команды нужны лишь для входа в меню
(/start, /menu). Мастер добавления собирает данные (панель → сервер → доступ →
inbound'ы → донор/страна → сквады → подтверждение), заводит в БД Panel+Node и
ставит задачу provision_node в очередь arq; воркер гоняет конвейер и шлёт
статусы в этот же чат (orchestrator/reporting.py).

Секреты: пароль/ключ сервера и токен панели в payload задачи не кладём — он
лежит в Redis открытым текстом до выборки воркером. Доступ-секрет bootstrap
пишем в Vault на транзитный путь и отдаём воркеру только путь; воркер стирает
его сразу после bootstrap. Токен панели тоже в Vault, в payload — лишь путь.
В БД секретов нет, только пути (Panel.token_vault_path).

Состояние мастера (FSM) хранится в Redis (см. bot/__main__.py), поэтому
незавершённый диалог и сохранённая панель/ноды переживают перезапуск бота.
"""
from __future__ import annotations

import logging
import re

from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message
from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from bot import keyboards
from bot.callbacks import AddCfgCB, MenuCB, NodeCB, PanelCB, WizCB
from bot.states import AddNode, AdoptNode, SetPanel
from config import settings
from orchestrator import domain
from orchestrator.ssh_bootstrap import _generate_keypair
from orchestrator.xray_config import REALITY_CHOICES, TLS_CHOICES, InboundChoice

logger = logging.getLogger(__name__)
router = Router()

# Меню inbound'ов (ADR 0005), все шесть пунктов в порядке ADR. Пункты 3 и 5 —
# TLS, им нужен домен: при их выборе мастер уходит на шаг ввода домена, дальше
# воркер проверяет резолв и выпускает сертификат. Остальные — domain-free.
INBOUND_MENU: tuple[tuple[str, InboundChoice, str], ...] = (
    ("1", InboundChoice.VLESS_REALITY_TCP, "VLESS + Reality (TCP)"),
    ("2", InboundChoice.VLESS_XHTTP_REALITY, "VLESS + XHTTP + Reality"),
    ("3", InboundChoice.VLESS_XHTTP_TLS, "VLESS + XHTTP + TLS (нужен домен)"),
    ("4", InboundChoice.VLESS_GRPC_REALITY, "VLESS + gRPC + Reality"),
    ("5", InboundChoice.TROJAN_WS_TLS, "Trojan + WS + TLS (нужен домен)"),
    ("6", InboundChoice.SHADOWSOCKS, "Shadowsocks"),
    ("7", InboundChoice.HYSTERIA2, "Hysteria2 (нужен домен)"),
)
_MENU_BY_NUMBER = {num: choice for num, choice, _ in INBOUND_MENU}

# Код страны ноды: ровно две буквы (ISO 3166-1 alpha-2). Существование кода не
# проверяем — панели важен формат, на UX-уровне этого достаточно.
_COUNTRY_RE = re.compile(r"^[a-z]{2}$")

# Пул arq на процесс бота. Создаётся лениво при первой постановке задачи.
_queue: ArqRedis | None = None


# --------------------------------------------------------------------------
# Чистые помощники (разбор ввода и сборка payload). Тестируются отдельно.
# --------------------------------------------------------------------------
def selection_needs_domain(inbounds: list[str] | None) -> bool:
    """Нужен ли домен для выбранного набора.

    None («все/по умолчанию») доменом не считаем: дефолт у воркера domain-free,
    домен спрашиваем только при явном выборе TLS-инбаунда (ADR 0005)."""
    if not inbounds:
        return False
    tls_values = {c.value for c in TLS_CHOICES}
    return any(v in tls_values for v in inbounds)


def selection_has_reality(inbounds: list[str] | None) -> bool:
    """Есть ли среди выбранного Reality-инбаунд — только им нужен донор (ADR 0007).

    None («все/по умолчанию») считаем содержащим Reality: дефолтный набор воркера
    почти весь на Reality, так что донор спросить уместно."""
    if not inbounds:
        return True
    reality_values = {c.value for c in REALITY_CHOICES}
    return any(v in reality_values for v in inbounds)


def parse_reality_donor(text: str) -> tuple[str, list[str]] | None:
    """Разобрать ввод донора Reality (ADR 0007).

    Пусто / «default» → None: воркер подставит дефолт (www.microsoft.com). Иначе
    из хоста собираем (dest «host:443», server_names [host]); порт можно задать
    явно через двоеточие. Некорректный хост/порт → ValueError."""
    raw = (text or "").strip().lower()
    if raw in ("", "default", "дефолт", "по умолчанию", "-"):
        return None

    s = raw
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.split("/", 1)[0]                 # отрезаем путь, если вставили URL
    host, sep, port = s.partition(":")
    host = domain.normalize_domain(host)
    if not domain.is_valid_domain(host):
        raise ValueError(host or s)
    if sep:
        if not port.isdigit():
            raise ValueError(s)
        dest = f"{host}:{port}"
    else:
        dest = f"{host}:443"
    return dest, [host]


def parse_country_code(text: str) -> str | None:
    """Разобрать код страны ноды. Пусто/«skip» → None (воркер подставит «XX»).
    Две буквы → код в верхнем регистре. Иначе ValueError."""
    raw = (text or "").strip().lower()
    if raw in ("", "skip", "пропустить", "-"):
        return None
    if not _COUNTRY_RE.match(raw):
        raise ValueError(raw)
    return raw.upper()


def parse_inbounds(text: str) -> list[str] | None:
    """Разобрать выбор inbound'ов из текста (запасной ввод для тех, кто печатает).

    Возвращает список значений InboundChoice, либо None для «все/по умолчанию».
    Дубли схлопываются с сохранением порядка. Неизвестный пункт → ValueError."""
    raw = (text or "").strip().lower()
    if raw in ("", "all", "все"):
        return None

    chosen: list[str] = []
    for token in re.split(r"[\s,]+", raw):
        if not token:
            continue
        choice = _MENU_BY_NUMBER.get(token)
        if choice is None:
            raise ValueError(token)
        if choice.value not in chosen:
            chosen.append(choice.value)
    return chosen or None


def parse_squad_selection(text: str, options: list[dict]) -> list[str] | None:
    """Разобрать выбор сквадов из текста (запасной ввод).

    options — список {uuid, name} в порядке показа. Пусто/«all» → None («во все»).
    Иначе номера из списка → список uuid'ов без дублей. Неизвестный → ValueError."""
    raw = (text or "").strip().lower()
    if raw in ("", "all", "все"):
        return None
    chosen: list[str] = []
    for token in re.split(r"[\s,]+", raw):
        if not token:
            continue
        if not token.isdigit() or not (1 <= int(token) <= len(options)):
            raise ValueError(token)
        uuid = options[int(token) - 1]["uuid"]
        if uuid not in chosen:
            chosen.append(uuid)
    return chosen or None


def toggle_value(selected: list[str], value: str) -> list[str]:
    """Переключить значение в списке выбора (для тоглов inbound'ов)."""
    if value in selected:
        return [v for v in selected if v != value]
    return [*selected, value]


def toggle_index(selected: list[int], idx: int) -> list[int]:
    """Переключить индекс в списке выбора (для тоглов сквадов)."""
    if idx in selected:
        return [i for i in selected if i != idx]
    return [*selected, idx]


def build_payload(
    data: dict, *, node_id: int, chat_id: int,
    secret_vault_path: str, panel_token_vault_path: str,
) -> dict:
    """Собрать payload задачи provision_node из данных FSM.

    Секреты в payload не кладём: он сериализуется в Redis открытым текстом, пока
    воркер не заберёт задачу. Сам пароль/ключ доступа и токен панели лежат в
    Vault, а в payload идут только пути к ним: secret_vault_path (транзитный
    bootstrap-секрет {"auth", "password"|"private_key"}) и panel_token_vault_path
    (токен панели по panels/{owner}/token). auth остаётся в payload — это лишь
    признак способа доступа («password»/«key»), не секрет.

    node_id/chat_id нужны воркеру для отчётности.
    """
    payload: dict = {
        "node_id": node_id,
        "chat_id": chat_id,
        "ip": data["ip"],
        "login": data.get("login", "root"),
        "auth": data["auth"],
        "panel_mode": data.get("panel_mode", "existing"),
        "secret_vault_path": secret_vault_path,
        "panel_token_vault_path": panel_token_vault_path,
    }

    if data.get("panel_url"):
        payload["panel_url"] = data["panel_url"]
    if data.get("inbounds"):
        payload["inbounds"] = data["inbounds"]
    if data.get("tls_domain"):
        payload["tls_domain"] = data["tls_domain"]
    # Донор Reality per-node (ADR 0007). Не задан → не кладём, воркер возьмёт
    # дефолт. dest и server_names идут парой.
    if data.get("reality_dest"):
        payload["reality_dest"] = data["reality_dest"]
        payload["reality_server_names"] = data.get("reality_server_names", [])
    if data.get("country_code"):
        payload["country_code"] = data["country_code"]
    # Сквады для привязки (ADR 0008). Не заданы → не кладём, воркер добавит во все.
    if data.get("squad_uuids"):
        payload["squad_uuids"] = data["squad_uuids"]
    return payload


# Требования панели к паролю супер-админа (см. контракт 2.7.x): длина >= 24,
# минимум одна заглавная, одна строчная, одна цифра. Валидируем в мастере, чтобы
# не гонять заведомо отклонённый пароль до самой регистрации.
ADMIN_PASSWORD_MIN_LEN = 24


def validate_admin_password(password: str) -> str | None:
    """Проверить пароль супер-админа панели на сложность.

    Возвращает None, если пароль годится, иначе — текст ошибки для оператора
    (понятный, без раскрытия самого пароля). Требования диктует панель: длина
    не меньше 24, минимум одна заглавная, одна строчная и одна цифра."""
    pwd = password or ""
    if len(pwd) < ADMIN_PASSWORD_MIN_LEN:
        return f"Пароль должен быть не короче {ADMIN_PASSWORD_MIN_LEN} символов."
    if not any(c.islower() for c in pwd):
        return "В пароле нужна хотя бы одна строчная буква."
    if not any(c.isupper() for c in pwd):
        return "В пароле нужна хотя бы одна заглавная буква."
    if not any(c.isdigit() for c in pwd):
        return "В пароле нужна хотя бы одна цифра."
    return None


def build_panel_payload(
    data: dict, *, owner: int, chat_id: int,
    admin_secret_vault_path: str, secret_vault_path: str | None = None,
) -> dict:
    """Собрать payload задачи provision_panel из данных мастера (режим «new»).

    Секреты в payload не кладём — он лежит в Redis открытым текстом до выборки
    воркером. Пароль админа и (для vps) доступ-секрет bootstrap пишутся в Vault
    на транзитные пути, в payload идут только пути: admin_secret_vault_path и
    secret_vault_path. Для размещения «local» серверного доступа нет, поэтому
    ip/login/auth/secret_vault_path не добавляем.
    """
    placement = data.get("placement", "vps")
    payload: dict = {
        "owner": owner,
        "chat_id": chat_id,
        "placement": placement,
        "panel_domain": data["panel_domain"],
        "admin_username": data["admin_username"],
        "admin_secret_vault_path": admin_secret_vault_path,
    }
    if placement == "vps":
        payload["ip"] = data["ip"]
        payload["login"] = data.get("login", "root")
        payload["auth"] = data["auth"]
        payload["secret_vault_path"] = secret_vault_path
    return payload


def _panel_confirm_summary(data: dict) -> str:
    """Сводка перед запуском разворота панели: что именно уйдёт воркеру."""
    placement = data.get("placement", "vps")
    where = "отдельный VPS" if placement == "vps" else "этот сервер"
    lines = [
        "Проверь параметры панели:",
        f"• Размещение: {where}",
        f"• Домен: {data.get('panel_domain', '—')}",
        f"• Логин админа: {data.get('admin_username', '—')}",
        "• Пароль админа: задан (не показывается)",
    ]
    if placement == "vps":
        lines.append(
            f"• Сервер: {data.get('ip', '—')} (логин {data.get('login', 'root')})"
        )
        lines.append(
            f"• Доступ: {'пароль' if data.get('auth') == 'password' else 'ключ'}"
        )
    return "\n".join(lines)


def _confirm_summary(data: dict) -> str:
    """Сводка перед запуском: что именно уйдёт воркеру."""
    inbounds = data.get("inbounds")
    chosen = "все" if not inbounds else ", ".join(inbounds)
    lines = [
        "Проверь параметры ноды:",
        f"• Сервер: {data.get('ip', '—')} (логин {data.get('login', 'root')})",
        f"• Доступ: {'пароль' if data.get('auth') == 'password' else 'ключ'}",
        f"• Inbound'ы: {chosen}",
    ]
    if selection_has_reality(inbounds):
        dest = data.get("reality_dest")
        lines.append(f"• Донор Reality: {dest if dest else 'www.microsoft.com (по умолчанию)'}")
    cc = data.get("country_code")
    lines.append(f"• Страна: {cc if cc else 'XX (не указана)'}")
    if data.get("tls_domain"):
        lines.append(f"• Домен: {data['tls_domain']}")
    squad_uuids = data.get("squad_uuids")
    options = data.get("squad_options", [])
    if squad_uuids:
        names = [o["name"] for o in options if o["uuid"] in squad_uuids]
        lines.append(f"• Сквады: {', '.join(names) if names else 'выбранные'}")
    else:
        lines.append("• Сквады: все (по умолчанию)")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Доступ к БД / Vault / очереди.
# --------------------------------------------------------------------------
def _make_client(url: str, token: str):
    """Сборка клиента панели (импорт ленивый — без пакета remnawave модуль бота
    всё равно импортируется; в тестах подменяется именно эта граница)."""
    from orchestrator.remnawave_client import RemnawaveClient

    return RemnawaveClient(url, token)


async def _load_saved_panel(owner: int) -> tuple[str, str] | None:
    """URL и токен сохранённой панели владельца, либо None.

    URL берём из БД, токен — из Vault. Любая ошибка чтения (нет панели, Vault
    недоступен, пустой токен) → None: бот попросит данные панели заново."""
    from db import get_sessionmaker
    from db.repo import get_saved_panel
    from secretstore.vault import VaultStore

    panel = await get_saved_panel(get_sessionmaker(), owner)
    if panel is None:
        return None
    url, token_path = panel.url, panel.token_vault_path
    try:
        token = (VaultStore().get(token_path) or {}).get("token", "")
    except Exception as exc:  # noqa: BLE001 — нет секрета/Vault недоступен
        logger.warning("не удалось прочитать токен панели из Vault: %s", exc)
        return None
    if not token:
        return None
    return url, token


async def _save_panel(owner: int, url: str, token: str) -> None:
    """Сохранить панель владельца: токен в Vault, метаданные в БД."""
    from db import get_sessionmaker
    from db.repo import get_or_create_panel
    from secretstore.vault import VaultStore

    token_path = f"panels/{owner}/token"
    VaultStore().put(token_path, {"token": token})
    await get_or_create_panel(
        get_sessionmaker(), owner_tg_id=owner, url=url, token_vault_path=token_path
    )


async def _get_queue() -> ArqRedis:
    global _queue
    if _queue is None:
        _queue = await create_pool(
            RedisSettings(host=settings.redis_host, port=settings.redis_port)
        )
    return _queue


def _owner_of(event: Message | CallbackQuery) -> int:
    return event.from_user.id if event.from_user else 0


async def _render(
    event: Message | CallbackQuery, text: str, kb=None, *, html: bool = False
) -> None:
    """Показать шаг: на callback редактируем текущее сообщение, на текстовом
    вводе отправляем новое. Так UI не плодит лишних сообщений на нажатиях."""
    pm = "HTML" if html else None
    if isinstance(event, CallbackQuery):
        await event.message.edit_text(text, reply_markup=kb, parse_mode=pm)
    else:
        await event.answer(text, reply_markup=kb, parse_mode=pm)


# --------------------------------------------------------------------------
# Главное меню.
# --------------------------------------------------------------------------
_MENU_TEXT = (
    "Деплойер нод Remnawave.\n\n"
    "• Добавить ноду — пройти мастер и запустить установку.\n"
    "• Мои ноды — список добавленных нод и их статус.\n"
    "• Панель — какая панель сейчас привязана."
)


@router.message(CommandStart())
@router.message(Command("menu"))
async def start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(_MENU_TEXT, reply_markup=keyboards.main_menu())


@router.callback_query(MenuCB.filter(F.action == "home"))
async def menu_home(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await _render(query, _MENU_TEXT, keyboards.main_menu())
    await query.answer()


# --------------------------------------------------------------------------
# Раздел «Мои ноды».
# --------------------------------------------------------------------------
def _node_detail_text(node, live: str | None = None) -> str:
    shown = live or node.state
    lines = [
        f"{keyboards.state_badge(shown)} Нода #{node.id}",
        f"IP: {node.ip}",
        f"Состояние: {shown}",
    ]
    if node.remnawave_uuid:
        lines.append(f"UUID в панели: {node.remnawave_uuid}")
    if node.created_at:
        lines.append(f"Добавлена: {node.created_at:%Y-%m-%d %H:%M}")
    if live:
        lines.append("(статус получен из панели)")
    return "\n".join(lines)


async def _live_status(owner: int, node) -> str | None:
    """Живой статус ноды из панели по её uuid; None, если недоступно."""
    if not getattr(node, "remnawave_uuid", None):
        return None
    saved = await _load_saved_panel(owner)
    if not saved:
        return None
    url, token = saved
    try:
        client = _make_client(url, token)
        status = await client.get_node_status(node.remnawave_uuid)
    except Exception as exc:  # noqa: BLE001 — статус не должен ронять экран
        logger.warning("не удалось получить статус ноды из панели: %s", exc)
        return None
    value = getattr(status, "value", str(status))
    # Освежаем Node.state в БД, чтобы список «Мои ноды» не показывал протухший
    # статус до следующего прохода фонового поллера (ADR 0013).
    try:
        from db import get_sessionmaker
        from db.repo import set_node_state

        await set_node_state(get_sessionmaker(), node.id, value)
    except Exception as exc:  # noqa: BLE001 — запись статуса не должна ронять экран
        logger.warning("не удалось сохранить статус ноды в БД: %s", exc)
    return value


@router.callback_query(MenuCB.filter(F.action == "nodes"))
async def menu_nodes(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    from db import get_sessionmaker
    from db.repo import list_nodes_for_owner

    nodes = await list_nodes_for_owner(get_sessionmaker(), _owner_of(query))
    if not nodes:
        await _render(query, "Пока нет добавленных нод.", keyboards.nodes_list([]))
    else:
        await _render(query, "Твои ноды:", keyboards.nodes_list(nodes))
    await query.answer()


@router.callback_query(MenuCB.filter(F.action == "sync"))
async def menu_nodes_sync(query: CallbackQuery, state: FSMContext) -> None:
    """Подтянуть ноды, заведённые в панели не через бота, в локальный список.

    Импорт по запросу (а не на привязке панели): оператор сам решает, тащить ли
    старые ноды, и привязка панели не тормозит. Дедуп по (panel_id, uuid) в
    repo.import_panel_node, поэтому повторный синк не плодит дубли. Состояние
    импортированной ноды — живой статус панели. SSH-ключа от чужих нод нет:
    они частично функциональны (виден статус, но нет действий по SSH)."""
    await state.clear()
    owner = _owner_of(query)
    from db import get_sessionmaker
    from db.repo import (
        get_saved_panel,
        import_panel_node,
        list_nodes_for_owner,
        set_node_state_by_uuid,
    )

    sm = get_sessionmaker()
    panel = await get_saved_panel(sm, owner)
    if panel is None:
        await query.answer("Сначала привяжи панель в разделе «Панель».", show_alert=True)
        return
    saved = await _load_saved_panel(owner)
    if not saved:
        await query.answer("Не удалось прочитать токен панели из Vault.", show_alert=True)
        return
    url, token = saved
    try:
        client = _make_client(url, token)
        panel_nodes = await client.list_nodes()
    except Exception as exc:  # noqa: BLE001 — недоступность панели не должна ронять экран
        logger.warning("синк нод: не удалось получить список из панели: %s", exc)
        await query.answer("Панель недоступна, попробуй позже.", show_alert=True)
        return

    created = 0
    refreshed = 0
    for n in panel_nodes:
        if await import_panel_node(
            sm, panel_id=panel.id, remnawave_uuid=n.uuid, ip=n.address,
            state=n.status.value,
        ):
            created += 1
        # Нода уже была в списке — освежаем её статус из панели (живой статус
        # пришёл в том же ответе list_nodes). Так одна кнопка обновляет статусы
        # всех нод, не заходя в каждую по отдельности.
        elif await set_node_state_by_uuid(
            sm, panel_id=panel.id, remnawave_uuid=n.uuid, state=n.status.value,
        ):
            refreshed += 1

    nodes = await list_nodes_for_owner(sm, owner)
    if created:
        head = f"Импортировано новых нод: {created}."
    elif panel_nodes:
        head = "Новых нод нет — всё уже в списке."
    else:
        head = "В панели нет нод для импорта."
    if refreshed:
        head += f" Обновлены статусы: {refreshed}."
    text = f"{head}\n\nТвои ноды:" if nodes else head
    await _render(query, text, keyboards.nodes_list(nodes))
    await query.answer()


@router.callback_query(NodeCB.filter(F.action == "open"))
async def node_open(query: CallbackQuery, callback_data: NodeCB) -> None:
    from db import get_sessionmaker
    from db.repo import get_node_for_owner

    node = await get_node_for_owner(
        get_sessionmaker(), callback_data.node_id, _owner_of(query)
    )
    if node is None:
        await query.answer("Нода не найдена.", show_alert=True)
        return
    await _render(
        query, _node_detail_text(node),
        keyboards.node_actions(node.id, has_ssh=node.ssh_key_vault_path is not None),
    )
    await query.answer()


@router.callback_query(NodeCB.filter(F.action == "refresh"))
async def node_refresh(query: CallbackQuery, callback_data: NodeCB) -> None:
    from db import get_sessionmaker
    from db.repo import get_node_for_owner

    owner = _owner_of(query)
    node = await get_node_for_owner(get_sessionmaker(), callback_data.node_id, owner)
    if node is None:
        await query.answer("Нода не найдена.", show_alert=True)
        return
    live = await _live_status(owner, node)
    await _render(
        query, _node_detail_text(node, live),
        keyboards.node_actions(node.id, has_ssh=node.ssh_key_vault_path is not None),
    )
    await query.answer("Обновлено")


# --------------------------------------------------------------------------
# Добавление инбаунда к уже развёрнутой ноде (Фаза 3 Hysteria2).
# --------------------------------------------------------------------------
def _read_node_ssh(node_id: int) -> tuple[str | None, str]:
    """Приватный ключ и логин ноды из Vault (nodes/{id}/ssh). Логин по умолчанию
    root — для старых нод без логина рядом с ключом (как в node-операциях)."""
    from secretstore.vault import VaultStore

    try:
        data = VaultStore().get(f"nodes/{node_id}/ssh") or {}
    except Exception as exc:  # noqa: BLE001 — нет ключа/Vault недоступен
        logger.warning("addcfg: не прочитать ключ ноды %s: %s", node_id, exc)
        return None, "root"
    return data.get("private_key"), data.get("login", "root")


@router.callback_query(NodeCB.filter(F.action == "addcfg"))
async def node_addcfg_start(query: CallbackQuery, callback_data: NodeCB) -> None:
    """Показать список инбаундов, которые можно добавить к этой ноде.

    Совместимость считаем по текущему профилю ноды (что уже есть и есть ли домен)
    — см. xray_config.available_choices_for_node."""
    from db import get_sessionmaker
    from db.repo import get_node_for_owner
    from orchestrator.node_inbound import _extract_tls
    from orchestrator.xray_config import available_choices_for_node

    owner = _owner_of(query)
    node = await get_node_for_owner(get_sessionmaker(), callback_data.node_id, owner)
    if node is None:
        await query.answer("Нода не найдена.", show_alert=True)
        return
    if not node.ssh_key_vault_path:
        await query.answer("Нужен SSH-доступ — сначала удочери ноду.", show_alert=True)
        return
    if not node.remnawave_uuid:
        await query.answer("Нода не зарегистрирована в панели.", show_alert=True)
        return
    saved = await _load_saved_panel(owner)
    if not saved:
        await query.answer("Не удалось прочитать панель из Vault.", show_alert=True)
        return
    url, token = saved
    try:
        client = _make_client(url, token)
        node_cfg = await client.get_node_config(node.remnawave_uuid)
        profile = await client.get_config_profile(node_cfg.profile_uuid)
    except Exception as exc:  # noqa: BLE001 — недоступность панели не должна ронять экран
        logger.warning("addcfg: не прочитать профиль ноды %s: %s", node.id, exc)
        await query.answer("Панель недоступна, попробуй позже.", show_alert=True)
        return

    has_domain = _extract_tls(profile.config) is not None
    available = available_choices_for_node(
        list(profile.tag_to_inbound), has_domain=has_domain
    )
    if not available:
        await query.answer(
            "Все совместимые инбаунды уже есть на ноде.", show_alert=True
        )
        return
    options = [
        (num, label) for num, choice, label in INBOUND_MENU if choice in available
    ]
    await _render(
        query,
        f"Добавить инбаунд на ноду {node.ip}.\n"
        "Выбери, что добавить (порт подберётся автоматически):",
        keyboards.add_inbound_kb(node.id, options),
    )
    await query.answer()


@router.callback_query(AddCfgCB.filter())
async def node_addcfg_pick(query: CallbackQuery, callback_data: AddCfgCB) -> None:
    """Выполнить добавление выбранного инбаунда к ноде (inline, как удочерение)."""
    from db import get_sessionmaker
    from db.repo import get_node_for_owner

    owner = _owner_of(query)
    node = await get_node_for_owner(get_sessionmaker(), callback_data.node_id, owner)
    if node is None:
        await query.answer("Нода не найдена.", show_alert=True)
        return
    choice = _MENU_BY_NUMBER.get(callback_data.num)
    if choice is None:
        await query.answer("Неизвестный инбаунд.", show_alert=True)
        return
    saved = await _load_saved_panel(owner)
    if not saved:
        await query.answer("Не удалось прочитать панель из Vault.", show_alert=True)
        return
    priv, login = _read_node_ssh(node.id)
    if not priv:
        await query.answer("Нет SSH-ключа ноды в Vault.", show_alert=True)
        return

    url, token = saved
    await _render(query, f"Добавляю инбаунд на {node.ip} — это займёт минуту…")
    from orchestrator import node_ops
    from orchestrator.node_inbound import add_inbound_to_node

    try:
        client = _make_client(url, token)
        res = await add_inbound_to_node(
            choice=choice, ip=node.ip, node_uuid=node.remnawave_uuid,
            country_code="XX", ssh_login=login, ssh_private_key=priv,
            client=client, open_port=node_ops.open_port,
            probe_ports=node_ops.listening_ports,
        )
        detail = res.detail
    except Exception as exc:  # noqa: BLE001 — сбой добавления не должен ронять бот
        logger.warning("addcfg: добавление инбаунда на ноду %s упало: %s", node.id, exc)
        detail = f"Не удалось добавить инбаунд: {exc}"

    await _render(
        query, detail,
        keyboards.node_actions(node.id, has_ssh=node.ssh_key_vault_path is not None),
    )
    await query.answer()


@router.callback_query(NodeCB.filter(F.action == "ask_delete"))
async def node_ask_delete(query: CallbackQuery, callback_data: NodeCB) -> None:
    await _render(
        query,
        "Убрать ноду из списка деплойера?\n"
        "Запись и ключ забудутся. Контейнер на сервере и запись в панели "
        "останутся — это только список бота.",
        keyboards.node_delete_confirm(callback_data.node_id),
    )
    await query.answer()


@router.callback_query(NodeCB.filter(F.action == "delete"))
async def node_delete(query: CallbackQuery, callback_data: NodeCB) -> None:
    from db import get_sessionmaker
    from db.repo import delete_node, list_nodes_for_owner

    owner = _owner_of(query)
    ok = await delete_node(get_sessionmaker(), callback_data.node_id, owner)
    nodes = await list_nodes_for_owner(get_sessionmaker(), owner)
    text = "Нода убрана из списка." if ok else "Нода уже отсутствует."
    if nodes:
        text += "\n\nТвои ноды:"
    else:
        text += "\n\nПока нет добавленных нод."
    await _render(query, text, keyboards.nodes_list(nodes))
    await query.answer()


# --------------------------------------------------------------------------
# Удочерение импортированной ноды: дать ей SSH-доступ (ADR 0013).
# --------------------------------------------------------------------------
async def _adopt_node(
    node_id: int, ip: str, login: str, password: str
) -> tuple[bool, str]:
    """Поставить наш ключ на сервер импортированной ноды и сохранить доступ.

    Переиспользуем bootstrap по паролю (детекция окружения + установка ключа +
    проверка входа по нему), кладём приватный ключ в Vault по тому же пути, что и
    при обычном провижене (nodes/{id}/ssh), и пишем путь в БД. После этого нода
    становится полноценной: действия по SSH начинают работать. Пароль приходит
    параметром, используется один раз и не сохраняется."""
    from db import get_sessionmaker
    from db.repo import set_node_fields
    from orchestrator import ssh_bootstrap
    from secretstore.vault import VaultStore

    result = await ssh_bootstrap.bootstrap_password(ip, login, password)
    if not result.ok or not result.private_key:
        return False, result.detail or "не удалось подключиться к серверу"

    key_path = f"nodes/{node_id}/ssh"
    try:
        # Логин кладём рядом с ключом — он нужен поздним SSH-действиям (ADR 0013).
        VaultStore().put(
            key_path, {"private_key": result.private_key, "login": login}
        )
    except Exception as exc:  # noqa: BLE001 — без сохранённого ключа доступа нет смысла
        logger.warning("удочерение: ключ получен, но не сохранён в Vault: %s", exc)
        return False, f"ключ получен, но не сохранён в Vault: {exc}"

    await set_node_fields(
        get_sessionmaker(), node_id, ssh_key_vault_path=key_path
    )
    return True, "Готово: ключ установлен, нодой теперь можно управлять."


@router.callback_query(NodeCB.filter(F.action == "adopt"))
async def node_adopt_start(
    query: CallbackQuery, callback_data: NodeCB, state: FSMContext
) -> None:
    from db import get_sessionmaker
    from db.repo import get_node_for_owner

    node = await get_node_for_owner(
        get_sessionmaker(), callback_data.node_id, _owner_of(query)
    )
    if node is None:
        await query.answer("Нода не найдена.", show_alert=True)
        return
    if node.ssh_key_vault_path:
        await query.answer("У ноды уже есть SSH-доступ.", show_alert=True)
        return
    await state.set_state(AdoptNode.wait_login)
    await state.update_data(adopt_node_id=node.id, adopt_ip=node.ip)
    await _render(
        query,
        f"Удочерение ноды {node.ip}.\n"
        "Пришли логин для входа на сервер (обычно root):",
        keyboards.cancel_only(),
    )
    await query.answer()


@router.message(AdoptNode.wait_login)
async def node_adopt_login(message: Message, state: FSMContext) -> None:
    login = (message.text or "").strip()
    if not login:
        await message.answer(
            "Пустой логин. Пришли логин (например, root).",
            reply_markup=keyboards.cancel_only(),
        )
        return
    await state.update_data(adopt_login=login)
    await state.set_state(AdoptNode.wait_password)
    await message.answer(
        "Пришли пароль для входа. Он используется один раз, чтобы поставить "
        "ключ, и нигде не сохраняется.",
        reply_markup=keyboards.cancel_only(),
    )


@router.message(AdoptNode.wait_password)
async def node_adopt_password(message: Message, state: FSMContext) -> None:
    # Пароль не логируем и держим только до постановки ключа (как wiz_password).
    password = message.text or ""
    data = await state.get_data()
    await state.clear()
    node_id = data.get("adopt_node_id")
    ip = data.get("adopt_ip")
    login = data.get("adopt_login")

    owner = _owner_of(message)
    from db import get_sessionmaker
    from db.repo import get_node_for_owner

    node = await get_node_for_owner(get_sessionmaker(), node_id, owner)
    if node is None:
        await message.answer("Нода не найдена.", reply_markup=keyboards.main_menu())
        return

    await message.answer(f"Подключаюсь к {ip} и ставлю ключ — это займёт минуту…")
    try:
        ok, detail = await _adopt_node(node_id, ip, login, password)
    except Exception as exc:  # noqa: BLE001 — сбой удочерения не должен ронять бот
        logger.warning("удочерение ноды %s упало: %s", node_id, exc)
        ok, detail = False, f"непредвиденный сбой: {exc}"
    finally:
        del password

    node = await get_node_for_owner(get_sessionmaker(), node_id, owner)
    await message.answer(
        detail,
        reply_markup=keyboards.node_actions(
            node_id, has_ssh=bool(node and node.ssh_key_vault_path)
        ),
    )


# --------------------------------------------------------------------------
# Действия по SSH над развёрнутой нодой: перезапуск / ребут (ADR 0013).
# --------------------------------------------------------------------------
def _load_node_key(vault_path: str) -> tuple[str, str] | None:
    """Достать (private_key, login) ноды из Vault по её пути ключа.

    Логин лежит рядом с ключом (см. _store_key/_adopt_node); у старых нод его
    может не быть — тогда дефолтим на root (типовой логин VPS). None — если
    ключа нет или Vault недоступен."""
    from secretstore.vault import VaultStore

    try:
        data = VaultStore().get(vault_path) or {}
    except Exception as exc:  # noqa: BLE001 — нет ключа/Vault недоступен
        logger.warning("не удалось прочитать ключ ноды из Vault: %s", exc)
        return None
    key = data.get("private_key")
    if not key:
        return None
    return key, data.get("login") or "root"


async def _ssh_node(query: CallbackQuery, node_id: int, action) -> None:
    """Общий каркас SSH-действия: проверить владельца/ключ, выполнить, отчитаться.

    action — корутина (ip, login, private_key) -> OpResult (restart/reboot)."""
    from db import get_sessionmaker
    from db.repo import get_node_for_owner

    owner = _owner_of(query)
    node = await get_node_for_owner(get_sessionmaker(), node_id, owner)
    if node is None:
        await query.answer("Нода не найдена.", show_alert=True)
        return
    if not node.ssh_key_vault_path:
        await query.answer("У ноды нет SSH-доступа. Сначала удочери её.", show_alert=True)
        return
    creds = _load_node_key(node.ssh_key_vault_path)
    if creds is None:
        await query.answer("Не удалось прочитать SSH-ключ ноды из Vault.", show_alert=True)
        return
    private_key, login = creds

    await query.answer("Выполняю…")
    try:
        result = await action(node.ip, login, private_key)
        detail = result.detail
    except Exception as exc:  # noqa: BLE001 — сбой действия не должен ронять бот
        logger.warning("SSH-действие над нодой %s упало: %s", node_id, exc)
        detail = f"Непредвиденный сбой: {exc}"
    await _render(
        query, detail,
        keyboards.node_actions(node_id, has_ssh=True),
    )


@router.callback_query(NodeCB.filter(F.action == "restart"))
async def node_restart(query: CallbackQuery, callback_data: NodeCB) -> None:
    from orchestrator import node_ops

    await _ssh_node(query, callback_data.node_id, node_ops.restart_node)


@router.callback_query(NodeCB.filter(F.action == "ask_reboot"))
async def node_ask_reboot(query: CallbackQuery, callback_data: NodeCB) -> None:
    await _render(
        query,
        "Перезагрузить сервер ноды целиком?\n"
        "Нода ненадолго пропадёт и вернётся сама через пару минут. Имеет смысл, "
        "когда забита память и перезапуск контейнера не помогает.",
        keyboards.node_reboot_confirm(callback_data.node_id),
    )
    await query.answer()


@router.callback_query(NodeCB.filter(F.action == "reboot"))
async def node_reboot(query: CallbackQuery, callback_data: NodeCB) -> None:
    from orchestrator import node_ops

    await _ssh_node(query, callback_data.node_id, node_ops.reboot_server)


# --------------------------------------------------------------------------
# Раздел «Панель».
# --------------------------------------------------------------------------
@router.callback_query(MenuCB.filter(F.action == "panel"))
async def menu_panel(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    saved = await _load_saved_panel(_owner_of(query))
    if saved:
        url, _ = saved
        text = f"Текущая панель: {url}"
    else:
        text = "Панель пока не привязана. Подключи её один раз — дальше мастер не будет спрашивать."
    await _render(query, text, keyboards.panel_menu(saved is not None))
    await query.answer()


@router.callback_query(PanelCB.filter(F.action == "change"))
async def panel_change(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(SetPanel.wait_url)
    await _render(query, "Пришли URL панели (https://...):", keyboards.cancel_only())
    await query.answer()


@router.message(SetPanel.wait_url)
async def setpanel_url(message: Message, state: FSMContext) -> None:
    url = (message.text or "").strip()
    if not url.startswith(("http://", "https://")):
        await message.answer("Нужен URL вида https://panel.example.", reply_markup=keyboards.cancel_only())
        return
    await state.update_data(panel_url=url)
    await state.set_state(SetPanel.wait_token)
    await message.answer("Пришли API-токен панели:", reply_markup=keyboards.cancel_only())


@router.message(SetPanel.wait_token)
async def setpanel_token(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    await _save_panel(_owner_of(message), data["panel_url"], (message.text or "").strip())
    await state.clear()
    await message.answer(
        f"Панель сохранена: {data['panel_url']}.\nТеперь добавление ноды не будет спрашивать панель.",
        reply_markup=keyboards.main_menu(),
    )


# --------------------------------------------------------------------------
# Мастер добавления ноды.
# --------------------------------------------------------------------------
@router.callback_query(MenuCB.filter(F.action == "add"))
async def add_start(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    owner = _owner_of(query)
    saved = await _load_saved_panel(owner)
    if saved:
        url, token = saved
        await state.update_data(panel_mode="existing", panel_url=url, panel_token=token)
        await state.set_state(AddNode.wait_ip)
        await _render(query, f"Панель: {url} (сохранена).\n\nПришли IP сервера:", keyboards.cancel_only())
        await query.answer()
        return
    await state.set_state(AddNode.choose_panel_mode)
    await _render(query, "Подключить существующую панель или развернуть с нуля?", keyboards.panel_mode())
    await query.answer()


@router.callback_query(WizCB.filter(F.action == "cancel"))
async def wiz_cancel(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await _render(query, _MENU_TEXT, keyboards.main_menu())
    await query.answer("Отменено")


@router.callback_query(AddNode.choose_panel_mode, WizCB.filter(F.action == "pm"))
async def wiz_panel_mode(query: CallbackQuery, callback_data: WizCB, state: FSMContext) -> None:
    if callback_data.val == "new":
        # Сценарий временно отключён флагом, пока не проверен на живом сервере.
        # Кнопку прячем в клавиатуре, но страхуемся и от старого callback.
        if not settings.panel_from_scratch_enabled:
            await query.answer(
                "Разворот панели с нуля временно недоступен.", show_alert=True
            )
            return
        # Разворот панели с нуля (ADR 0001): сперва выбираем размещение, дальше
        # домен/логин/пароль и (для vps) доступ к серверу — см. wiz_placement.
        await state.update_data(panel_mode="new")
        await state.set_state(AddNode.choose_placement)
        await _render(
            query,
            "Где развернуть панель?",
            keyboards.placement_choice(),
        )
        await query.answer()
        return
    await state.update_data(panel_mode="existing")
    await state.set_state(AddNode.wait_panel_url)
    await _render(query, "Пришли URL панели (https://...):", keyboards.cancel_only())
    await query.answer()


@router.message(AddNode.wait_panel_url)
async def wiz_panel_url(message: Message, state: FSMContext) -> None:
    url = (message.text or "").strip()
    if not url.startswith(("http://", "https://")):
        await message.answer("Нужен URL вида https://panel.example.", reply_markup=keyboards.cancel_only())
        return
    await state.update_data(panel_url=url)
    await state.set_state(AddNode.wait_panel_token)
    await message.answer("Пришли API-токен панели:", reply_markup=keyboards.cancel_only())


@router.message(AddNode.wait_panel_token)
async def wiz_panel_token(message: Message, state: FSMContext) -> None:
    await state.update_data(panel_token=(message.text or "").strip())
    await state.set_state(AddNode.wait_ip)
    await message.answer("Пришли IP сервера:", reply_markup=keyboards.cancel_only())


@router.message(AddNode.wait_ip)
async def wiz_ip(message: Message, state: FSMContext) -> None:
    await state.update_data(ip=(message.text or "").strip())
    await state.set_state(AddNode.wait_login)
    await message.answer("SSH-логин (или нажми кнопку для root):", reply_markup=keyboards.login_default())


@router.message(AddNode.wait_login)
async def wiz_login_text(message: Message, state: FSMContext) -> None:
    await state.update_data(login=(message.text or "").strip() or "root")
    await state.set_state(AddNode.choose_auth)
    await message.answer("Как заходить на сервер?", reply_markup=keyboards.auth_choice())


@router.callback_query(AddNode.wait_login, WizCB.filter(F.action == "login"))
async def wiz_login_default(query: CallbackQuery, state: FSMContext) -> None:
    await state.update_data(login="root")
    await state.set_state(AddNode.choose_auth)
    await _render(query, "Как заходить на сервер?", keyboards.auth_choice())
    await query.answer()


@router.callback_query(AddNode.choose_auth, WizCB.filter(F.action == "auth"))
async def wiz_auth(query: CallbackQuery, callback_data: WizCB, state: FSMContext) -> None:
    auth = callback_data.val
    await state.update_data(auth=auth)
    if auth == "password":
        await state.set_state(AddNode.wait_password)
        await _render(query, "Пришли пароль (используется один раз, не сохраняется):", keyboards.cancel_only())
        await query.answer()
        return
    # Ветка «ключ»: генерим per-node пару, отдаём оператору one-liner с pubkey.
    private_key, public_key = _generate_keypair()
    await state.update_data(private_key=private_key)
    await state.set_state(AddNode.wait_key_added)
    one_liner = (
        "mkdir -p ~/.ssh &amp;&amp; chmod 700 ~/.ssh &amp;&amp; "
        f"echo '{public_key}' &gt;&gt; ~/.ssh/authorized_keys &amp;&amp; "
        "chmod 600 ~/.ssh/authorized_keys"
    )
    await _render(
        query,
        "Выполни на сервере под нужным пользователем:\n\n"
        f"<code>{one_liner}</code>\n\n"
        "Затем нажми кнопку.",
        keyboards.key_added(),
        html=True,
    )
    await query.answer()


@router.message(AddNode.wait_password)
async def wiz_password(message: Message, state: FSMContext) -> None:
    # Пароль не логируем. Держим в FSM только до постановки задачи.
    await state.update_data(password=(message.text or ""))
    data = await state.get_data()
    if data.get("panel_mode") == "new":
        # Разворот панели на vps: доступ к серверу собран, inbound'ы тут не нужны.
        await _go_panel_confirm_step(message, state)
        return
    await _show_inbounds(message, state)


@router.callback_query(AddNode.wait_key_added, WizCB.filter(F.action == "keyok"))
async def wiz_key_added(query: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    if data.get("panel_mode") == "new":
        await _go_panel_confirm_step(query, state)
        await query.answer()
        return
    await _show_inbounds(query, state)
    await query.answer()


async def _show_inbounds(event: Message | CallbackQuery, state: FSMContext) -> None:
    await state.update_data(inb_selected=[])
    await state.set_state(AddNode.choose_inbounds)
    await _render(
        event,
        "Какие inbound'ы поднять? Отметь нужные и нажми «Готово», либо «Все».",
        keyboards.inbounds_kb(INBOUND_MENU, []),
    )


@router.callback_query(AddNode.choose_inbounds, WizCB.filter(F.action == "inb"))
async def wiz_inbounds(query: CallbackQuery, callback_data: WizCB, state: FSMContext) -> None:
    val = callback_data.val
    data = await state.get_data()
    selected: list[str] = data.get("inb_selected", [])

    if val == "all":
        await state.update_data(inbounds=None, inb_selected=[])
        await query.answer("Выбраны все")
        await _after_inbounds(query, state, None)
        return
    if val == "done":
        inbounds = selected or None
        await state.update_data(inbounds=inbounds)
        await query.answer()
        await _after_inbounds(query, state, inbounds)
        return

    choice = _MENU_BY_NUMBER.get(val)
    if choice is None:
        await query.answer()
        return
    selected = toggle_value(selected, choice.value)
    await state.update_data(inb_selected=selected)
    await query.message.edit_reply_markup(reply_markup=keyboards.inbounds_kb(INBOUND_MENU, selected))
    await query.answer()


async def _after_inbounds(event, state: FSMContext, inbounds: list[str] | None) -> None:
    """После выбора inbound'ов: TLS требует домена (ADR 0005), иначе сразу донор."""
    if selection_needs_domain(inbounds):
        await state.set_state(AddNode.wait_domain)
        await _render(
            event,
            "Для TLS-инбаунда нужен домен. Пришли поддомен для этой ноды (например vpn.example.com):",
            keyboards.cancel_only(),
        )
        return
    await _go_donor_step(event, state)


@router.message(AddNode.wait_domain)
async def wiz_domain(message: Message, state: FSMContext) -> None:
    domain_name = domain.normalize_domain(message.text or "")
    if not domain.is_valid_domain(domain_name):
        await message.answer("Не похоже на домен. Например vpn.example.com.", reply_markup=keyboards.cancel_only())
        return
    await state.update_data(tls_domain=domain_name)
    data = await state.get_data()
    ip = data.get("ip", "&lt;IP ноды&gt;")
    await message.answer(
        f"Домен: {domain_name}.\n\n"
        "Создай у регистратора A-запись:\n"
        f"<code>{domain_name} → {ip}</code>\n"
        "и дождись применения. Перед выпуском сертификата я проверю резолв.",
        parse_mode="HTML",
    )
    await _go_donor_step(message, state)


async def _go_donor_step(event, state: FSMContext) -> None:
    data = await state.get_data()
    if selection_has_reality(data.get("inbounds")):
        await state.set_state(AddNode.wait_reality_dest)
        await _render(
            event,
            "Сайт-донор для маскировки Reality (ADR 0007).\n"
            "Для ноды за границей нужен иностранный сайт на TLS1.3+H2, доступный из РФ.\n"
            "Пришли домен донора (например www.cloudflare.com) или нажми кнопку для дефолта.",
            keyboards.donor_kb(),
        )
        return
    await _go_country_step(event, state)


@router.message(AddNode.wait_reality_dest)
async def wiz_reality_text(message: Message, state: FSMContext) -> None:
    try:
        donor = parse_reality_donor(message.text or "")
    except ValueError:
        await message.answer(
            "Не похоже на домен. Например www.cloudflare.com, или нажми кнопку для дефолта.",
            reply_markup=keyboards.donor_kb(),
        )
        return
    if donor is not None:
        dest, server_names = donor
        await state.update_data(reality_dest=dest, reality_server_names=server_names)
    await _go_country_step(message, state)


@router.callback_query(AddNode.wait_reality_dest, WizCB.filter(F.action == "donor"))
async def wiz_reality_default(query: CallbackQuery, state: FSMContext) -> None:
    await _go_country_step(query, state)
    await query.answer()


async def _go_country_step(event, state: FSMContext) -> None:
    await state.set_state(AddNode.wait_country)
    await _render(
        event,
        "Код страны ноды (ISO-2, например NL, DE, US) — показывается в панели. "
        "Пришли код или нажми «Пропустить».",
        keyboards.country_kb(),
    )


@router.message(AddNode.wait_country)
async def wiz_country_text(message: Message, state: FSMContext) -> None:
    try:
        code = parse_country_code(message.text or "")
    except ValueError:
        await message.answer("Нужен код из двух букв (например NL) или «Пропустить».", reply_markup=keyboards.country_kb())
        return
    if code is not None:
        await state.update_data(country_code=code)
    await _go_squads_step(message, state)


@router.callback_query(AddNode.wait_country, WizCB.filter(F.action == "cc"))
async def wiz_country_skip(query: CallbackQuery, state: FSMContext) -> None:
    await _go_squads_step(query, state)
    await query.answer()


async def _go_squads_step(event, state: FSMContext) -> None:
    """Показать сквады панели на выбор (ADR 0008). Панель недоступна/сквадов нет —
    не блокируем: сразу к подтверждению, воркер добавит ноду во все сквады."""
    data = await state.get_data()
    url, token = data.get("panel_url"), data.get("panel_token")
    squads = []
    if url and token:
        try:
            client = _make_client(url, token)
            squads = await client.list_internal_squads()
        except Exception as exc:  # noqa: BLE001 — мастер не должен падать из-за сети
            logger.warning("не удалось получить сквады панели: %s", exc)
            squads = []
    if not squads:
        await _go_confirm_step(event, state)
        return
    options = [{"uuid": s.uuid, "name": s.name} for s in squads]
    await state.update_data(squad_options=options, sq_selected=[])
    await state.set_state(AddNode.choose_squads)
    await _render(
        event,
        "В какие внутренние сквады добавить ноду, чтобы её увидели пользователи?\n"
        "Отметь нужные и нажми «Готово», либо «Все».",
        keyboards.squads_kb(options, []),
    )


@router.callback_query(AddNode.choose_squads, WizCB.filter(F.action == "sq"))
async def wiz_squads(query: CallbackQuery, callback_data: WizCB, state: FSMContext) -> None:
    val = callback_data.val
    data = await state.get_data()
    options = data.get("squad_options", [])
    selected: list[int] = data.get("sq_selected", [])

    if val == "all":
        await state.update_data(squad_uuids=None, sq_selected=[])
        await query.answer("Выбраны все")
        await _go_confirm_step(query, state)
        return
    if val == "done":
        uuids = [options[i]["uuid"] for i in selected if 0 <= i < len(options)]
        await state.update_data(squad_uuids=uuids or None)
        await query.answer()
        await _go_confirm_step(query, state)
        return

    if not val.isdigit() or not (0 <= int(val) < len(options)):
        await query.answer()
        return
    selected = toggle_index(selected, int(val))
    await state.update_data(sq_selected=selected)
    await query.message.edit_reply_markup(reply_markup=keyboards.squads_kb(options, selected))
    await query.answer()


async def _go_confirm_step(event, state: FSMContext) -> None:
    await state.set_state(AddNode.confirm)
    data = await state.get_data()
    await _render(event, _confirm_summary(data), keyboards.confirm_kb())


@router.callback_query(AddNode.confirm, WizCB.filter(F.action == "go"))
async def wiz_confirm(query: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    # Один шаг подтверждения на оба сценария: добавление ноды и разворот панели.
    # Разводим по panel_mode, чтобы не плодить два фильтра на одном состоянии.
    if data.get("panel_mode") == "new":
        await _confirm_panel(query, state, data)
        return
    from db import get_sessionmaker
    from db.repo import create_node_record, get_or_create_panel

    owner = _owner_of(query)
    ip = data["ip"]
    await _save_panel(owner, data["panel_url"], data.get("panel_token", ""))

    sm = get_sessionmaker()
    token_path = f"panels/{owner}/token"
    panel_id = await get_or_create_panel(
        sm, owner_tg_id=owner, url=data["panel_url"], token_vault_path=token_path
    )
    node_id = await create_node_record(sm, panel_id=panel_id, ip=ip)

    # Секреты не идут в payload очереди (он лежит в Redis открытым текстом до
    # того, как воркер заберёт задачу). Доступ-секрет bootstrap кладём в Vault
    # на транзитный путь и передаём воркеру только путь; токен панели воркер
    # возьмёт из panels/{owner}/token, куда его уже положил _save_panel.
    from secretstore.vault import VaultStore

    secret_path = f"transient/nodes/{node_id}/bootstrap"
    if data.get("auth") == "password":
        bootstrap_secret = {"auth": "password", "password": data.get("password", "")}
    else:
        bootstrap_secret = {"auth": "key", "private_key": data.get("private_key", "")}
    VaultStore().put(secret_path, bootstrap_secret)

    payload = build_payload(
        data, node_id=node_id, chat_id=query.message.chat.id,
        secret_vault_path=secret_path, panel_token_vault_path=token_path,
    )
    queue = await _get_queue()
    await queue.enqueue_job("provision_node", payload)

    logger.info("enqueue provision_node node_id=%s ip=%s auth=%s", node_id, ip, data.get("auth"))
    await state.clear()
    await _render(
        query,
        "Задача поставлена. Статусы установки буду присылать сюда.",
        keyboards.to_menu(),
    )
    await query.answer("Запущено")


# --------------------------------------------------------------------------
# Мастер разворота панели с нуля (режим «new», ADR 0001).
# --------------------------------------------------------------------------
@router.callback_query(AddNode.choose_placement, WizCB.filter(F.action == "plc"))
async def wiz_placement(query: CallbackQuery, callback_data: WizCB, state: FSMContext) -> None:
    placement = callback_data.val if callback_data.val in ("vps", "local") else "vps"
    await state.update_data(placement=placement)
    await state.set_state(AddNode.wait_panel_domain)
    await _render(
        query,
        "Домен для панели (например panel.example.com). На него Caddy выпустит "
        "сертификат — заранее создай A-запись на сервер панели.",
        keyboards.cancel_only(),
    )
    await query.answer()


@router.message(AddNode.wait_panel_domain)
async def wiz_panel_domain(message: Message, state: FSMContext) -> None:
    domain_name = domain.normalize_domain(message.text or "")
    if not domain.is_valid_domain(domain_name):
        await message.answer(
            "Не похоже на домен. Например panel.example.com.",
            reply_markup=keyboards.cancel_only(),
        )
        return
    await state.update_data(panel_domain=domain_name)
    await state.set_state(AddNode.wait_admin_username)
    await message.answer(
        "Логин супер-админа панели (его будешь вводить при входе):",
        reply_markup=keyboards.cancel_only(),
    )


@router.message(AddNode.wait_admin_username)
async def wiz_admin_username(message: Message, state: FSMContext) -> None:
    username = (message.text or "").strip()
    if not username:
        await message.answer(
            "Логин не может быть пустым. Пришли логин супер-админа.",
            reply_markup=keyboards.cancel_only(),
        )
        return
    await state.update_data(admin_username=username)
    await state.set_state(AddNode.wait_admin_password)
    await message.answer(
        "Пароль супер-админа. Требования панели: не короче 24 символов, "
        "минимум одна заглавная, одна строчная буква и одна цифра.",
        reply_markup=keyboards.cancel_only(),
    )


@router.message(AddNode.wait_admin_password)
async def wiz_admin_password(message: Message, state: FSMContext) -> None:
    # Пароль не логируем. Держим в FSM только до постановки задачи (как пароль
    # доступа к серверу). Сначала проверяем сложность — панель отклонит слабый.
    password = message.text or ""
    error = validate_admin_password(password)
    if error is not None:
        await message.answer(
            f"{error} Пришли пароль ещё раз.",
            reply_markup=keyboards.cancel_only(),
        )
        return
    await state.update_data(admin_password=password)
    data = await state.get_data()
    if data.get("placement") == "local":
        # Локальный разворот: сервер не нужен, сразу к подтверждению.
        await _go_panel_confirm_step(message, state)
        return
    # Разворот на vps: дальше общие шаги доступа к серверу (IP → логин → способ).
    await state.set_state(AddNode.wait_ip)
    await message.answer(
        "Теперь сервер панели. Пришли IP сервера:",
        reply_markup=keyboards.cancel_only(),
    )


async def _go_panel_confirm_step(event, state: FSMContext) -> None:
    await state.set_state(AddNode.confirm)
    data = await state.get_data()
    await _render(event, _panel_confirm_summary(data), keyboards.confirm_kb())


async def _confirm_panel(query: CallbackQuery, state: FSMContext, data: dict) -> None:
    """Запуск разворота панели: транзитные секреты в Vault, задача в очередь.

    Пароль админа (и для vps — доступ-секрет bootstrap) пишем в Vault на
    транзитные пути и отдаём воркеру только пути; в payload очереди секретов нет.
    Panel в БД здесь не создаём — её запишет воркер после успешного разворота
    (build_panel_deps), когда появится рабочий URL и токен.
    """
    from secretstore.vault import VaultStore

    owner = _owner_of(query)
    chat_id = query.message.chat.id
    placement = data.get("placement", "vps")

    vault = VaultStore()
    admin_secret_path = f"transient/panels/{owner}/admin"
    vault.put(admin_secret_path, {"password": data.get("admin_password", "")})

    secret_path = None
    if placement == "vps":
        secret_path = f"transient/panels/{owner}/bootstrap"
        if data.get("auth") == "password":
            bootstrap_secret = {"auth": "password", "password": data.get("password", "")}
        else:
            bootstrap_secret = {"auth": "key", "private_key": data.get("private_key", "")}
        vault.put(secret_path, bootstrap_secret)

    payload = build_panel_payload(
        data, owner=owner, chat_id=chat_id,
        admin_secret_vault_path=admin_secret_path, secret_vault_path=secret_path,
    )
    queue = await _get_queue()
    await queue.enqueue_job("provision_panel", payload)

    logger.info(
        "enqueue provision_panel owner=%s placement=%s domain=%s",
        owner, placement, data.get("panel_domain"),
    )
    await state.clear()
    await _render(
        query,
        "Задача поставлена. Статусы разворота панели буду присылать сюда.",
        keyboards.to_menu(),
    )
    await query.answer("Запущено")
