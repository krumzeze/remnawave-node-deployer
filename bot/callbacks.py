"""Фабрики callback_data для inline-кнопок бота.

Управление ботом идёт кнопками, а не командами: каждое нажатие приходит как
callback с упакованной сюда строкой (aiogram CallbackData). Держим строки
короткими — у Telegram лимит 64 байта на callback_data, поэтому в полезной
нагрузке только короткие коды и числовые id/индексы, без длинных uuid и url.
"""
from __future__ import annotations

from aiogram.filters.callback_data import CallbackData


class MenuCB(CallbackData, prefix="m"):
    """Главное меню и навигация между его разделами."""
    action: str  # home | add | nodes | sync | panel


class NodeCB(CallbackData, prefix="n"):
    """Действия над конкретной нодой из списка «Мои ноды»."""
    action: str  # open | refresh | adopt | restart | ask_reboot | reboot | ask_delete | delete
    node_id: int


class AddCfgCB(CallbackData, prefix="ac"):
    """Добавление инбаунда к уже развёрнутой ноде из её карточки.

    num — номер пункта INBOUND_MENU (как в WizCB.inb); по нему находим
    InboundChoice. Длинные значения в callback не кладём — лимит 64 байта."""
    node_id: int
    num: str  # номер пункта меню inbound'ов, либо "cancel"


class PanelCB(CallbackData, prefix="p"):
    """Раздел управления сохранённой панелью."""
    action: str  # change


class WizCB(CallbackData, prefix="w"):
    """Шаги мастера добавления ноды.

    val — короткий код шага: режим панели (existing/new), способ доступа
    (password/key), номер inbound'а для тогла, индекс сквада, служебные
    all/done/skip/default. Длинные значения (uuid сквадов, значения inbound'ов)
    в callback не кладём — храним выбор в FSM, в кнопке только индекс/номер.
    """
    action: str  # pm | plc | auth | keyok | inb | donor | cc | sq | go | cancel
    val: str = ""
