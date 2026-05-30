"""Хендлеры и FSM-диалог добавления ноды.

Скелет: переходы состояний намечены, реальная валидация и постановка задачи
в очередь помечены TODO. Пароль НИКОГДА не логируется и не сохраняется —
он идёт только в payload задачи bootstrap и стирается после использования.
"""
import logging

from aiogram import Router, F
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import Message

from bot.states import AddNode

logger = logging.getLogger(__name__)
router = Router()


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
    await state.update_data(panel_mode=mode)
    if mode == "existing":
        await state.set_state(AddNode.wait_panel_url)
        await message.answer("URL панели (https://...):")
    else:
        await state.set_state(AddNode.wait_ip)
        await message.answer("IP сервера:")


@router.message(AddNode.wait_panel_url)
async def wait_panel_url(message: Message, state: FSMContext) -> None:
    # TODO: валидировать URL, проверить доступность панели
    await state.update_data(panel_url=(message.text or "").strip())
    await state.set_state(AddNode.wait_panel_token)
    await message.answer("API-токен панели:")


@router.message(AddNode.wait_panel_token)
async def wait_panel_token(message: Message, state: FSMContext) -> None:
    # TODO: токен сохранить в Vault, в БД — только ссылку на секрет
    await state.update_data(panel_token=(message.text or "").strip())
    await state.set_state(AddNode.wait_ip)
    await message.answer("IP сервера:")


@router.message(AddNode.wait_ip)
async def wait_ip(message: Message, state: FSMContext) -> None:
    # TODO: валидировать IP
    await state.update_data(ip=(message.text or "").strip())
    await state.set_state(AddNode.choose_auth)
    await message.answer(
        "Способ доступа к серверу?\n"
        "password — я введу логин/пароль (бот переведёт сервер на ключ)\n"
        "key — я сам добавлю ваш публичный ключ (one-liner)"
    )


@router.message(AddNode.choose_auth)
async def choose_auth(message: Message, state: FSMContext) -> None:
    auth = (message.text or "").strip().lower()
    if auth not in {"password", "key"}:
        await message.answer("Введи password или key.")
        return
    await state.update_data(auth=auth)
    if auth == "password":
        await state.set_state(AddNode.wait_login)
        await message.answer("SSH-логин (обычно root):")
    else:
        # TODO: сгенерить per-node keypair, выдать one-liner с pubkey
        await state.set_state(AddNode.confirm)
        await message.answer(
            "Выполни на сервере one-liner (TODO), затем напиши: ok"
        )


@router.message(AddNode.wait_login)
async def wait_login(message: Message, state: FSMContext) -> None:
    await state.update_data(login=(message.text or "").strip())
    await state.set_state(AddNode.wait_password)
    await message.answer("Пароль (будет использован один раз и не сохранён):")


@router.message(AddNode.wait_password)
async def wait_password(message: Message, state: FSMContext) -> None:
    # ВАЖНО: пароль не логируем. Держим только в FSM до постановки задачи.
    await state.update_data(password=(message.text or ""))
    await state.set_state(AddNode.confirm)
    await message.answer("Всё готово. Запустить? Напиши: ok")


@router.message(AddNode.confirm, F.text.lower() == "ok")
async def confirm(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    # TODO: enqueue arq-задачу provision_node(data); пароль — только в payload
    #       задачи, не в БД; после bootstrap стирается.
    logger.info("enqueue provision_node ip=%s mode=%s auth=%s",
                data.get("ip"), data.get("panel_mode"), data.get("auth"))
    await state.clear()
    await message.answer("Задача поставлена. Статус буду присылать сюда.")
