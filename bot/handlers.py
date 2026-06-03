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
from orchestrator.xray_config import TLS_CHOICES, InboundChoice

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
    return payload


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

    # TLS-инбаунд требует домена (ADR 0005) — уводим на шаг ввода домена.
    if selection_needs_domain(inbounds):
        await state.set_state(AddNode.wait_domain)
        await message.answer(
            "Для TLS-инбаунда нужен домен. Введи поддомен для этой ноды "
            "(например vpn.example.com)."
        )
        return

    await state.set_state(AddNode.confirm)
    chosen = "все" if inbounds is None else ", ".join(inbounds)
    await message.answer(f"Inbound'ы: {chosen}.\nЗапустить? Напиши: ok")


@router.message(AddNode.wait_domain)
async def wait_domain(message: Message, state: FSMContext) -> None:
    domain_name = domain.normalize_domain(message.text or "")
    if not domain.is_valid_domain(domain_name):
        await message.answer("Не похоже на домен. Введи, например, vpn.example.com.")
        return
    await state.update_data(tls_domain=domain_name)
    await state.set_state(AddNode.confirm)

    data = await state.get_data()
    inbounds = data.get("inbounds")
    chosen = "все" if not inbounds else ", ".join(inbounds)
    ip = data.get("ip", "<IP ноды>")
    # Generic-инструкция A-записи (registrar-agnostic, ADR 0005): саму запись
    # создаёт оператор у своего регистратора, мы лишь говорим, что нужно. Перед
    # выпуском сертификата воркер сам проверит, что домен уже указывает на ноду.
    await message.answer(
        f"Inbound'ы: {chosen}.\n"
        f"Домен: {domain_name}.\n\n"
        "Создай у регистратора A-запись:\n"
        f"<code>{domain_name} → {ip}</code>\n"
        "и дождись, пока она применится. Перед выпуском сертификата я проверю, "
        "что домен резолвится на ноду.\n\n"
        "Когда A-запись создана — напиши: ok",
        parse_mode="HTML",
    )


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
