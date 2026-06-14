"""Тесты построителей клавиатур и тогл-логики выбора.

Сетевую часть aiogram не трогаем — проверяем, что кнопки несут правильные
callback_data (их потом ловят хендлеры) и что отметки выбора расставляются
верно. Тогл-функции живут в handlers (там же, где разбор ввода)."""
from __future__ import annotations

from aiogram.filters.callback_data import CallbackData

from bot import handlers, keyboards
from bot.callbacks import MenuCB, NodeCB, PanelSettingsCB, WizCB
from bot.handlers import INBOUND_MENU


def _all_buttons(markup):
    return [btn for row in markup.inline_keyboard for btn in row]


def test_toggle_value_adds_and_removes():
    assert handlers.toggle_value([], "a") == ["a"]
    assert handlers.toggle_value(["a"], "b") == ["a", "b"]
    assert handlers.toggle_value(["a", "b"], "a") == ["b"]


def test_toggle_index_adds_and_removes():
    assert handlers.toggle_index([], 0) == [0]
    assert handlers.toggle_index([0], 2) == [0, 2]
    assert handlers.toggle_index([0, 2], 0) == [2]


def test_state_badge_known_and_unknown():
    assert keyboards.state_badge("online") == "🟢"
    assert keyboards.state_badge("failed") == "🔴"
    assert keyboards.state_badge("queued") == "⏳"
    assert keyboards.state_badge("weird") == "⚪️"


def test_main_menu_has_three_actions():
    actions = []
    for btn in _all_buttons(keyboards.main_menu()):
        actions.append(MenuCB.unpack(btn.callback_data).action)
    assert actions == ["add", "nodes", "panel"]


def test_inbounds_kb_marks_selected():
    selected = [INBOUND_MENU[0][1].value]  # первый inbound выбран
    markup = keyboards.inbounds_kb(INBOUND_MENU, selected)
    texts = [b.text for b in _all_buttons(markup)]
    assert any(t.startswith("✅") for t in texts)        # есть отмеченный
    assert sum(t.startswith("✅") for t in texts) == 1   # ровно один
    # «Все», «Готово», «Отмена» присутствуют как inb/cancel
    vals = [WizCB.unpack(b.callback_data).val for b in _all_buttons(markup)
            if b.callback_data.startswith("w:")]
    assert "all" in vals and "done" in vals


def test_squads_kb_toggle_marks():
    options = [{"uuid": "u1", "name": "all"}, {"uuid": "u2", "name": "vip"}]
    markup = keyboards.squads_kb(options, [1])
    texts = [b.text for b in _all_buttons(markup)]
    assert "✅ vip" in texts
    assert "▫️ all" in texts


def test_panel_menu_shows_settings_only_with_panel():
    # Кнопка настроек панели появляется только когда панель привязана.
    cbs = [b.callback_data for b in _all_buttons(keyboards.panel_menu(True))]
    assert any(c.startswith("ps:") for c in cbs)
    cbs_none = [b.callback_data for b in _all_buttons(keyboards.panel_menu(False))]
    assert not any(c.startswith("ps:") for c in cbs_none)


def test_panel_settings_menu_has_ru_bypass():
    actions = [
        PanelSettingsCB.unpack(b.callback_data).action
        for b in _all_buttons(keyboards.panel_settings_menu())
        if b.callback_data.startswith("ps:")
    ]
    assert "ru_bypass" in actions


def test_nodes_list_buttons_carry_node_id():
    class N:
        def __init__(self, i, ip, state):
            self.id, self.ip, self.state = i, ip, state
    markup = keyboards.nodes_list([N(7, "1.2.3.4", "online")])
    node_btns = [b for b in _all_buttons(markup) if b.callback_data.startswith("n:")]
    assert NodeCB.unpack(node_btns[0].callback_data).node_id == 7


def test_startup_module_imports():
    # __main__ тянет RedisStorage/init_models — проверяем, что импортируется.
    import importlib
    import bot.__main__ as m
    importlib.reload(m)
    assert hasattr(m, "main")
