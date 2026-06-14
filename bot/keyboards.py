"""Inline-клавиатуры бота.

Управление ботом построено на кнопках, а не на текстовых командах: и навигация
(меню, список нод, панель), и мастер добавления ноды собираются здесь как
InlineKeyboardMarkup. Сами обработчики нажатий лежат в bot/handlers.py, коды
кнопок — в bot/callbacks.py. Тексты держим короткими и однозначными.
"""
from __future__ import annotations

from aiogram.types import InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from bot.callbacks import MenuCB, NodeCB, PanelCB, PanelSettingsCB, WizCB
from config import settings

# Значок состояния ноды для списка. Состояния — из state-машины провижининга
# (orchestrator/statemachine.py): queued → bootstrapping → provisioning →
# registering → online, плюс failed/rolled_back.
_STATE_EMOJI = {
    "queued": "⏳",
    "bootstrapping": "🟡",
    "provisioning": "🟡",
    "registering": "🟡",
    "online": "🟢",
    "failed": "🔴",
    "rolled_back": "🔴",
}


def state_badge(state: str) -> str:
    """Значок состояния; для неизвестного — нейтральный кружок."""
    return _STATE_EMOJI.get(state, "⚪️")


def _cancel_button(builder: InlineKeyboardBuilder) -> None:
    builder.button(text="✖️ Отмена", callback_data=WizCB(action="cancel"))


def main_menu() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="➕ Добавить ноду", callback_data=MenuCB(action="add"))
    b.button(text="🖥 Мои ноды", callback_data=MenuCB(action="nodes"))
    b.button(text="⚙️ Панель", callback_data=MenuCB(action="panel"))
    b.adjust(1)
    return b.as_markup()


def to_menu() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="⬅️ В меню", callback_data=MenuCB(action="home"))
    return b.as_markup()


def nodes_list(nodes) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    for n in nodes:
        b.button(
            text=f"{state_badge(n.state)} {n.ip} — {n.state}",
            callback_data=NodeCB(action="open", node_id=n.id),
        )
    b.button(text="➕ Добавить ноду", callback_data=MenuCB(action="add"))
    b.button(text="⬅️ В меню", callback_data=MenuCB(action="home"))
    b.adjust(1)
    return b.as_markup()


def node_actions(node_id: int) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="🔄 Обновить статус", callback_data=NodeCB(action="refresh", node_id=node_id))
    b.button(text="🗑 Убрать ноду", callback_data=NodeCB(action="ask_delete", node_id=node_id))
    b.button(text="⬅️ К списку", callback_data=MenuCB(action="nodes"))
    b.adjust(1)
    return b.as_markup()


def node_delete_confirm(node_id: int) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="❌ Да, убрать из списка", callback_data=NodeCB(action="delete", node_id=node_id))
    b.button(text="↩️ Отмена", callback_data=NodeCB(action="open", node_id=node_id))
    b.adjust(1)
    return b.as_markup()


def panel_menu(has_panel: bool) -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    label = "✏️ Сменить панель" if has_panel else "➕ Подключить панель"
    b.button(text=label, callback_data=PanelCB(action="change"))
    # Настройки панель-уровня доступны только когда панель привязана.
    if has_panel:
        b.button(text="⚙️ Настройки панели", callback_data=PanelSettingsCB(action="open"))
    b.button(text="⬅️ В меню", callback_data=MenuCB(action="home"))
    b.adjust(1)
    return b.as_markup()


def panel_settings_menu() -> InlineKeyboardMarkup:
    """Экран панель-уровневых настроек. Пока один пункт — обход РФ через Happ;
    сюда же лягут будущие настройки подписки/панели."""
    b = InlineKeyboardBuilder()
    b.button(text="🇷🇺 Включить обход РФ (Happ)", callback_data=PanelSettingsCB(action="ru_bypass"))
    b.button(text="⬅️ К панели", callback_data=MenuCB(action="panel"))
    b.adjust(1)
    return b.as_markup()


def cancel_only() -> InlineKeyboardMarkup:
    """Для шагов с вводом текста (IP, токен, домен) — только отмена."""
    b = InlineKeyboardBuilder()
    _cancel_button(b)
    return b.as_markup()


def panel_mode() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="Подключить существующую", callback_data=WizCB(action="pm", val="existing"))
    # Кнопка разворота с нуля скрыта, пока сценарий временно отключён флагом.
    if settings.panel_from_scratch_enabled:
        b.button(text="Развернуть с нуля", callback_data=WizCB(action="pm", val="new"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def placement_choice() -> InlineKeyboardMarkup:
    """Где развернуть панель с нуля (ADR 0001): на отдельном VPS (как ноды,
    через SSH) или на хосте деплойера (docker compose локально)."""
    b = InlineKeyboardBuilder()
    b.button(text="🌐 На отдельном VPS", callback_data=WizCB(action="plc", val="vps"))
    b.button(text="🏠 На этом сервере", callback_data=WizCB(action="plc", val="local"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def login_default() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="👤 root (по умолчанию)", callback_data=WizCB(action="login", val="root"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def auth_choice() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="🔑 По паролю", callback_data=WizCB(action="auth", val="password"))
    b.button(text="🗝 По ключу (one-liner)", callback_data=WizCB(action="auth", val="key"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def key_added() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="✅ Я добавил ключ", callback_data=WizCB(action="keyok"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def inbounds_kb(menu, selected: list[str]) -> InlineKeyboardMarkup:
    """Мультивыбор inbound'ов: галочка у выбранных, плюс «Все» и «Готово».

    menu — INBOUND_MENU (num, choice, label); selected — выбранные значения
    InboundChoice. Тоглим по номеру, поэтому в callback кладём только номер.
    """
    b = InlineKeyboardBuilder()
    for num, choice, label in menu:
        mark = "✅" if choice.value in selected else "▫️"
        b.button(text=f"{mark} {label}", callback_data=WizCB(action="inb", val=num))
    b.button(text="Все (по умолчанию)", callback_data=WizCB(action="inb", val="all"))
    b.button(text="➡️ Готово", callback_data=WizCB(action="inb", val="done"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def donor_kb() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="По умолчанию (www.microsoft.com)", callback_data=WizCB(action="donor", val="default"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def country_kb() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="Пропустить", callback_data=WizCB(action="cc", val="skip"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def squads_kb(options: list[dict], selected: list[int]) -> InlineKeyboardMarkup:
    """Мультивыбор сквадов: тоглим по индексу опции (uuid длинный, в callback
    не помещается — храним выбор в FSM, в кнопке только индекс)."""
    b = InlineKeyboardBuilder()
    for i, o in enumerate(options):
        mark = "✅" if i in selected else "▫️"
        b.button(text=f"{mark} {o['name']}", callback_data=WizCB(action="sq", val=str(i)))
    b.button(text="Все (по умолчанию)", callback_data=WizCB(action="sq", val="all"))
    b.button(text="➡️ Готово", callback_data=WizCB(action="sq", val="done"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()


def confirm_kb() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.button(text="🚀 Запустить", callback_data=WizCB(action="go"))
    _cancel_button(b)
    b.adjust(1)
    return b.as_markup()
