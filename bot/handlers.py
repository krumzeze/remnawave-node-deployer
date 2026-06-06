"""Хендлеры и FSM-диалог добавления ноды.

Диалог собирает данные (панель → сервер → доступ → inbound'ы), заводит в БД
Panel+Node и ставит задачу provision_node в очередь arq. Воркер дальше гоняет
конвейер и шлёт статусы обратно в этот же чат (см. orchestrator/reporting.py).

Секреты: пароль сервера идёт только в payload задачи и стирается в bootstrap,
в БД его нет. Токен панели кладём в Vault, в БД (Panel.token_vault_path) — лишь
путь. Приватный ключ ветки «ключ» генерим мы, в Vault его положит уже воркер
после проверки доступа.
"""
from __future__ import annotations

import logging
import re

from aiogram import F, Router
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import Message
from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from bot.states import AddNode
from config import settings
from orchestrator import domain
from orchestrator.ssh_bootstrap import _generate_keypair
from orchestrator.xray_config import REALITY_CHOICES, TLS_CHOICES, InboundChoice

logger = logging.getLogger(__name__)
router = Router()

# Меню inbound'ов (ADR 0005), все шесть пунктов в порядке ADR. Пункты 3 и 5 —
# TLS, им нужен домен: при их выборе диалог уходит на шаг ввода домена, дальше
# воркер проверяет резолв и выпускает сертификат (orchestrator/domain.py +
# issue_cert.yml). Остальные — domain-free.
INBOUND_MENU: tuple[tuple[str, InboundChoice, str], ...] = (
    ("1", InboundChoice.VLESS_REALITY_TCP, "VLESS + Reality (TCP)"),
    ("2", InboundChoice.VLESS_XHTTP_REALITY, "VLESS + XHTTP + Reality"),
    ("3", InboundChoice.VLESS_XHTTP_TLS, "VLESS + XHTTP + TLS (нужен домен)"),
    ("4", InboundChoice.VLESS_GRPC_REALITY, "VLESS + gRPC + Reality"),
    ("5", InboundChoice.TROJAN_WS_TLS, "Trojan + WS + TLS (нужен домен)"),
    ("6", InboundChoice.SHADOWSOCKS, "Shadowsocks"),
)
_MENU_BY_NUMBER = {num: choice for num, choice, _ in INBOUND_MENU}


def selection_needs_domain(inbounds: list[str] | None) -> bool:
    """Нужен ли домен для выбранного набора.

    None («все/по умолчанию») доменом не считаем: дефолт у воркера domain-free,
    домен спрашиваем только при явном выборе TLS-инбаунда (ADR 0005 — «домен
    запрашиваем, когда он реально нужен»)."""
    if not inbounds:
        return False
    tls_values = {c.value for c in TLS_CHOICES}
    return any(v in tls_values for v in inbounds)


def selection_has_reality(inbounds: list[str] | None) -> bool:
    """Есть ли среди выбранного Reality-инбаунд — только им нужен донор (ADR 0007).

    None («все/по умолчанию») считаем содержащим Reality: дефолтный набор воркера
    domain-free и почти весь на Reality, так что донор спросить уместно. Для
    набора без Reality (например только Shadowsocks/TLS) шаг донора пропускаем."""
    if not inbounds:
        return True
    reality_values = {c.value for c in REALITY_CHOICES}
    return any(v in reality_values for v in inbounds)


# Код страны ноды: ровно две буквы (ISO 3166-1 alpha-2). Существование кода не
# проверяем — панели важен формат, на UX-уровне этого достаточно.
_COUNTRY_RE = re.compile(r"^[a-z]{2}$")


def parse_reality_donor(text: str) -> tuple[str, list[str]] | None:
    """Разобрать ввод донора Reality (ADR 0007).

    Пусто / «default» → None: воркер подставит дефолт (www.microsoft.com). Иначе
    из хоста собираем (dest «host:443», server_names [host]); порт можно задать
    явно через двоеточие. Некорректный хост/порт → ValueError (для понятного
    переспроса в диалоге)."""
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
    """Разобрать код страны ноды для create_node.

    Пусто / «skip» → None: воркер подставит «XX». Две буквы → код в верхнем
    регистре. Иначе ValueError."""
    raw = (text or "").strip().lower()
    if raw in ("", "skip", "пропустить", "-"):
        return None
    if not _COUNTRY_RE.match(raw):
        raise ValueError(raw)
    return raw.upper()


# Пул arq на процесс бота. Создаётся лениво при первой постановке задачи.
_queue: ArqRedis | None = None


def _inbound_menu_text() -> str:
    lines = [f"{num} — {label}" for num, _, label in INBOUND_MENU]
    lines.append("all — все (по умолчанию)")
    return (
        "Какие inbound'ы поднять? Перечисли номера через пробел или запятую,\n"
        "либо напиши all (по умолчанию):\n\n" + "\n".join(lines)
    )


def parse_inbounds(text: str) -> list[str] | None:
    """Разобрать выбор inbound'ов из сообщения.

    Возвращает список значений InboundChoice, либо None для «все/по умолчанию»
    (None отдаём в payload как «не задано» — воркер подставит дефолтный набор).
    Дубли схлопываются с сохранением порядка. Неизвестный пункт → ValueError.
    """
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


def build_payload(data: dict, *, node_id: int, chat_id: int) -> dict:
    """Собрать payload задачи provision_node из данных FSM.

    node_id/chat_id нужны воркеру для отчётности; auth определяет, что кладём —
    password (стирается в bootstrap) или сгенерированный private_key.
    """
    payload: dict = {
        "node_id": node_id,
        "chat_id": chat_id,
        "ip": data["ip"],
        "login": data.get("login", "root"),
        "auth": data["auth"],
        "panel_mode": data.get("panel_mode", "existing"),
    }
    if data.get("auth") == "password":
        payload["password"] = data.get("password", "")
    else:
        payload["private_key"] = data.get("private_key", "")

    if data.get("panel_url"):
        payload["panel_url"] = data["panel_url"]
    if data.get("panel_token"):
        payload["panel_token"] = data["panel_token"]
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


def _reality_prompt() -> str:
    return (
        "Сайт-донор для маскировки Reality (ADR 0007).\n"
        "Для ноды за границей нужен иностранный сайт на TLS1.3+H2, доступный из "
        "РФ: отечественный SNI (vk/yandex) на зарубежном IP, наоборот, выдаёт "
        "соединение DPI.\n"
        "Введи домен донора (например www.cloudflare.com) или напиши default "
        "для www.microsoft.com."
    )


def _country_prompt() -> str:
    return (
        "Код страны ноды (ISO-2, например NL, DE, US) — показывается в панели.\n"
        "Можно пропустить — напиши skip."
    )


def _confirm_summary(data: dict) -> str:
    """Сводка перед запуском: что именно уйдёт воркеру."""
    inbounds = data.get("inbounds")
    chosen = "все" if not inbounds else ", ".join(inbounds)
    lines = [f"Inbound'ы: {chosen}."]
    if selection_has_reality(inbounds):
        dest = data.get("reality_dest")
        lines.append(
            f"Донор Reality: {dest if dest else 'www.microsoft.com (по умолчанию)'}."
        )
    cc = data.get("country_code")
    lines.append(f"Страна: {cc if cc else 'XX (не указана)'}.")
    if data.get("tls_domain"):
        lines.append(f"Домен: {data['tls_domain']}.")
    squad_uuids = data.get("squad_uuids")
    options = data.get("squad_options", [])
    if squad_uuids:
        names = [o["name"] for o in options if o["uuid"] in squad_uuids]
        lines.append(f"Сквады: {', '.join(names) if names else 'выбранные'}.")
    else:
        lines.append("Сквады: все (по умолчанию).")
    lines.append("\nЗапустить? Напиши: ok")
    return "\n".join(lines)


async def _go_donor_step(message: Message, state: FSMContext, data: dict) -> None:
    """После выбора inbound'ов (и домена для TLS) — спросить донор Reality, если
    среди выбранного он нужен, иначе сразу перейти к коду страны."""
    if selection_has_reality(data.get("inbounds")):
        await state.set_state(AddNode.wait_reality_dest)
        await message.answer(_reality_prompt())
    else:
        await _go_country_step(message, state)


async def _go_country_step(message: Message, state: FSMContext) -> None:
    await state.set_state(AddNode.wait_country)
    await message.answer(_country_prompt())


def _make_client(url: str, token: str):
    """Сборка клиента панели для шага сквадов. Вынесено отдельной функцией, чтобы
    тесты подменяли границу SDK (импорт ленивый — без пакета remnawave модуль
    бота всё равно импортируется)."""
    from orchestrator.remnawave_client import RemnawaveClient

    return RemnawaveClient(url, token)


def parse_squad_selection(text: str, options: list[dict]) -> list[str] | None:
    """Разобрать выбор сквадов из сообщения оператора.

    options — список {uuid, name} в порядке показа. Пусто / «all» → None («во все»,
    в payload не кладём — воркер сам подставит все сквады). Иначе номера из списка
    → список uuid'ов без дублей. Неизвестный номер → ValueError."""
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


def _squads_menu_text(options: list[dict]) -> str:
    lines = [f"{i} — {o['name']}" for i, o in enumerate(options, 1)]
    return (
        "В какие внутренние сквады добавить ноду, чтобы её увидели пользователи?\n"
        "Перечисли номера через пробел/запятую, либо напиши all (по умолчанию — "
        "во все):\n\n" + "\n".join(lines)
    )


async def _go_squads_step(message: Message, state: FSMContext, data: dict) -> None:
    """Перед подтверждением показать сквады панели на выбор (ADR 0008).

    Список тянем из панели по введённым ранее URL/токену. Если панель недоступна
    или сквадов нет — не блокируем диалог: молча переходим к подтверждению,
    воркер по умолчанию добавит ноду во все сквады."""
    url = data.get("panel_url")
    token = data.get("panel_token")
    squads = []
    if url and token:
        try:
            client = _make_client(url, token)
            squads = await client.list_internal_squads()
        except Exception as exc:  # noqa: BLE001 — диалог не должен падать из-за сети
            logger.warning("не удалось получить сквады панели: %s", exc)
            squads = []

    if not squads:
        await _go_confirm_step(message, state)
        return

    options = [{"uuid": s.uuid, "name": s.name} for s in squads]
    await state.update_data(squad_options=options)
    await state.set_state(AddNode.choose_squads)
    await message.answer(_squads_menu_text(options))


async def _go_confirm_step(message: Message, state: FSMContext) -> None:
    await state.set_state(AddNode.confirm)
    data = await state.get_data()
    await message.answer(_confirm_summary(data))


async def _get_queue() -> ArqRedis:
    global _queue
    if _queue is None:
        _queue = await create_pool(
            RedisSettings(host=settings.redis_host, port=settings.redis_port)
        )
    return _queue


@router.message(CommandStart())
async def start(message: Message) -> None:
    await message.answer(
        "Привет! Я добавляю ноды в Remnawave.\n"
        "Команда /add — добавить ноду."
    )


@router.message(F.text == "/add")
async def add_start(message: Message, state: FSMContext) -> None:
    await state.set_state(AddNode.choose_panel_mode)
    await message.answer(
        "Подключить существующую панель или развернуть с нуля?\n"
        "Ответь: existing | new"
    )


@router.message(AddNode.choose_panel_mode)
async def choose_panel_mode(message: Message, state: FSMContext) -> None:
    mode = (message.text or "").strip().lower()
    if mode not in {"existing", "new"}:
        await message.answer("Введи existing или new.")
        return
    if mode == "new":
        # Разворот панели с нуля — отдельный флоу (ADR 0001), он ещё не готов.
        # Конвейер такую задачу отклоняет, поэтому не доводим до постановки.
        await state.clear()
        await message.answer(
            "Разворот панели с нуля пока не реализован. "
            "Подключи существующую панель: /add → existing."
        )
        return
    await state.update_data(panel_mode=mode)
    await state.set_state(AddNode.wait_panel_url)
    await message.answer("URL панели (https://...):")


@router.message(AddNode.wait_panel_url)
async def wait_panel_url(message: Message, state: FSMContext) -> None:
    url = (message.text or "").strip()
    if not url.startswith(("http://", "https://")):
        await message.answer("Нужен URL вида https://panel.example.")
        return
    await state.update_data(panel_url=url)
    await state.set_state(AddNode.wait_panel_token)
    await message.answer("API-токен панели:")


@router.message(AddNode.wait_panel_token)
async def wait_panel_token(message: Message, state: FSMContext) -> None:
    await state.update_data(panel_token=(message.text or "").strip())
    await state.set_state(AddNode.wait_ip)
    await message.answer("IP сервера:")


@router.message(AddNode.wait_ip)
async def wait_ip(message: Message, state: FSMContext) -> None:
    await state.update_data(ip=(message.text or "").strip())
    await state.set_state(AddNode.wait_login)
    await message.answer("SSH-логин (обычно root):")


@router.message(AddNode.wait_login)
async def wait_login(message: Message, state: FSMContext) -> None:
    await state.update_data(login=(message.text or "").strip() or "root")
    await state.set_state(AddNode.choose_auth)
    await message.answer(
        "Способ доступа к серверу?\n"
        "password — введу логин/пароль (бот переведёт сервер на ключ)\n"
        "key — добавлю ваш публичный ключ сам (one-liner)"
    )


@router.message(AddNode.choose_auth)
async def choose_auth(message: Message, state: FSMContext) -> None:
    auth = (message.text or "").strip().lower()
    if auth not in {"password", "key"}:
        await message.answer("Введи password или key.")
        return
    await state.update_data(auth=auth)
    if auth == "password":
        await state.set_state(AddNode.wait_password)
        await message.answer("Пароль (будет использован один раз и не сохранён):")
        return

    # Ветка «ключ»: генерим per-node пару, отдаём оператору one-liner с pubkey.
    # Приватную часть держим в FSM до постановки задачи; в Vault её положит воркер.
    private_key, public_key = _generate_keypair()
    await state.update_data(private_key=private_key)
    await state.set_state(AddNode.wait_key_added)
    one_liner = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{public_key}' >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys"
    )
    await message.answer(
        "Выполни на сервере под нужным пользователем:\n\n"
        f"<code>{one_liner}</code>\n\n"
        "Когда добавишь ключ — напиши: ok",
        parse_mode="HTML",
    )


@router.message(AddNode.wait_key_added, F.text.lower() == "ok")
async def key_added(message: Message, state: FSMContext) -> None:
    await state.set_state(AddNode.choose_inbounds)
    await message.answer(_inbound_menu_text())


@router.message(AddNode.wait_password)
async def wait_password(message: Message, state: FSMContext) -> None:
    # Пароль не логируем. Держим в FSM только до постановки задачи.
    await state.update_data(password=(message.text or ""))
    await state.set_state(AddNode.choose_inbounds)
    await message.answer(_inbound_menu_text())


@router.message(AddNode.choose_inbounds)
async def choose_inbounds(message: Message, state: FSMContext) -> None:
    try:
        inbounds = parse_inbounds(message.text or "")
    except ValueError as exc:
        await message.answer(f"Не знаю пункт «{exc}». Введи номера из списка или all.")
        return
    await state.update_data(inbounds=inbounds)

    # TLS-инбаунд требует домена (ADR 0005) — уводим на шаг ввода домена. Дальше
    # (домен или сразу) — донор Reality и код страны, затем подтверждение.
    if selection_needs_domain(inbounds):
        await state.set_state(AddNode.wait_domain)
        await message.answer(
            "Для TLS-инбаунда нужен домен. Введи поддомен для этой ноды "
            "(например vpn.example.com)."
        )
        return

    await _go_donor_step(message, state, {"inbounds": inbounds})


@router.message(AddNode.wait_domain)
async def wait_domain(message: Message, state: FSMContext) -> None:
    domain_name = domain.normalize_domain(message.text or "")
    if not domain.is_valid_domain(domain_name):
        await message.answer("Не похоже на домен. Введи, например, vpn.example.com.")
        return
    await state.update_data(tls_domain=domain_name)

    data = await state.get_data()
    ip = data.get("ip", "<IP ноды>")
    # Generic-инструкция A-записи (registrar-agnostic, ADR 0005): саму запись
    # создаёт оператор у своего регистратора, мы лишь говорим, что нужно. Перед
    # выпуском сертификата воркер сам проверит, что домен уже указывает на ноду.
    # Финального «ok» здесь нет: дальше ещё спросим донор/страну, а подтверждение
    # запуска соберётся на шаге confirm.
    await message.answer(
        f"Домен: {domain_name}.\n\n"
        "Создай у регистратора A-запись:\n"
        f"<code>{domain_name} → {ip}</code>\n"
        "и дождись, пока она применится. Перед выпуском сертификата я проверю, "
        "что домен резолвится на ноду.",
        parse_mode="HTML",
    )
    await _go_donor_step(message, state, data)


@router.message(AddNode.wait_reality_dest)
async def wait_reality_dest(message: Message, state: FSMContext) -> None:
    try:
        donor = parse_reality_donor(message.text or "")
    except ValueError:
        await message.answer(
            "Не похоже на домен. Введи хост донора (например www.cloudflare.com) "
            "или напиши default."
        )
        return
    if donor is not None:
        dest, server_names = donor
        await state.update_data(reality_dest=dest, reality_server_names=server_names)
    await _go_country_step(message, state)


@router.message(AddNode.wait_country)
async def wait_country(message: Message, state: FSMContext) -> None:
    try:
        code = parse_country_code(message.text or "")
    except ValueError:
        await message.answer("Нужен код из двух букв (например NL) или skip.")
        return
    if code is not None:
        await state.update_data(country_code=code)
    await _go_squads_step(message, state, await state.get_data())


@router.message(AddNode.choose_squads)
async def choose_squads(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    options = data.get("squad_options", [])
    try:
        squad_uuids = parse_squad_selection(message.text or "", options)
    except ValueError as exc:
        await message.answer(
            f"Не знаю сквад «{exc}». Введи номера из списка или all."
        )
        return
    # None («все») в payload не кладём — воркер сам добавит во все сквады.
    if squad_uuids is not None:
        await state.update_data(squad_uuids=squad_uuids)
    await _go_confirm_step(message, state)


@router.message(AddNode.confirm, F.text.lower() == "ok")
async def confirm(message: Message, state: FSMContext) -> None:
    data = await state.get_data()

    from db import get_sessionmaker
    from db.repo import create_node_record, get_or_create_panel
    from secretstore.vault import VaultStore

    owner = message.from_user.id if message.from_user else 0
    ip = data["ip"]

    # Токен панели — в Vault; в БД только путь к нему (секрет в БД не пишем).
    token_path = f"panels/{owner}/token"
    VaultStore().put(token_path, {"token": data.get("panel_token", "")})

    sm = get_sessionmaker()
    panel_id = await get_or_create_panel(
        sm, owner_tg_id=owner, url=data["panel_url"], token_vault_path=token_path
    )
    node_id = await create_node_record(sm, panel_id=panel_id, ip=ip)

    payload = build_payload(data, node_id=node_id, chat_id=message.chat.id)
    queue = await _get_queue()
    await queue.enqueue_job("provision_node", payload)

    logger.info("enqueue provision_node node_id=%s ip=%s auth=%s",
                node_id, ip, data.get("auth"))
    await state.clear()
    await message.answer("Задача поставлена. Статус буду присылать сюда.")
