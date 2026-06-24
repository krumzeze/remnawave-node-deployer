"""Тесты построителей клавиатур и тогл-логики выбора.

Сетевую часть aiogram не трогаем — проверяем, что кнопки несут правильные
callback_data (их потом ловят хендлеры) и что отметки выбора расставляются
верно. Тогл-функции живут в handlers (там же, где разбор ввода)."""
from __future__ import annotations

from aiogram.filters.callback_data import CallbackData

from bot import handlers, keyboards
from bot.callbacks import AddCfgCB, MenuCB, NodeCB, WizCB
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


def test_state_badge_imported_statuses():
    # Импортированные ноды хранят живой статус панели — у него тоже есть значки.
    assert keyboards.state_badge("connecting") == "🟡"
    assert keyboards.state_badge("disabled") == "⏸"
    assert keyboards.state_badge("offline") == "🔴"


def test_nodes_list_has_sync_button():
    actions = [
        MenuCB.unpack(b.callback_data).action
        for b in _all_buttons(keyboards.nodes_list([]))
        if b.callback_data.startswith("m:")
    ]
    assert "sync" in actions


def test_node_actions_shows_adopt_only_without_ssh():
    # Импортированная нода (нет SSH-ключа) — есть кнопка «Удочерить»;
    # у полноценной её нет.
    def adopt_actions(markup):
        return [
            NodeCB.unpack(b.callback_data).action
            for b in _all_buttons(markup)
            if b.callback_data.startswith("n:")
        ]

    without = adopt_actions(keyboards.node_actions(1, has_ssh=False))
    withssh = adopt_actions(keyboards.node_actions(1, has_ssh=True))
    assert "adopt" in without
    assert "restart" not in without and "ask_reboot" not in without
    # С SSH-доступом — управление, без удочерения.
    assert "adopt" not in withssh
    assert "restart" in withssh and "ask_reboot" in withssh
    # «Добавить конфиг» доступно только при SSH (нужно открыть порт).
    assert "addcfg" in withssh
    assert "addcfg" not in without


def test_add_inbound_kb_carries_node_and_num():
    options = [("3", "VLESS + XHTTP + TLS"), ("7", "Hysteria2")]
    markup = keyboards.add_inbound_kb(42, options)
    picks = [
        AddCfgCB.unpack(b.callback_data)
        for b in _all_buttons(markup)
        if b.callback_data.startswith("ac:")
    ]
    assert {(p.node_id, p.num) for p in picks} == {(42, "3"), (42, "7")}
    # Кнопка отмены ведёт обратно к открытию ноды.
    cancels = [
        NodeCB.unpack(b.callback_data).action
        for b in _all_buttons(markup)
        if b.callback_data.startswith("n:")
    ]
    assert cancels == ["open"]


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
