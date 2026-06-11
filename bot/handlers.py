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
from bot.callbacks import MenuCB, NodeCB, PanelCB, WizCB
from bot.states import AddNode, SetPanel
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
    return getattr(status, "value", str(status))


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
    await _render(query, _node_detail_text(node), keyboards.node_actions(node.id))
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
    await _render(query, _node_detail_text(node, live), keyboards.node_actions(node.id))
    await query.answer("Обновлено")


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
        # Разворот панели с нуля — отдельный флоу (ADR 0001), он ещё не готов.
        await state.clear()
        await _render(
            query,
            "Разворот панели с нуля пока не реализован. Подключи существующую панель.",
            keyboards.main_menu(),
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
    await _show_inbounds(message, state)


@router.callback_query(AddNode.wait_key_added, WizCB.filter(F.action == "keyok"))
async def wiz_key_added(query: CallbackQuery, state: FSMContext) -> None:
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
