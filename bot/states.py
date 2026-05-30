"""FSM-состояния диалога добавления ноды.

Развилка аутентификации (ADR 0002): пользователь выбирает способ доступа —
по паролю (низкий порог) или по публичному ключу / one-liner (выше доверие).
Обе ветки сходятся в постановку задачи оркестратору.
"""
from aiogram.fsm.state import State, StatesGroup


class AddNode(StatesGroup):
    # Выбор: подключить существующую панель или развернуть с нуля (ADR 0001)
    choose_panel_mode = State()
    wait_panel_url = State()
    wait_panel_token = State()

    # Данные сервера
    wait_ip = State()
    choose_auth = State()      # пароль | ключ (ADR 0002)
    wait_login = State()
    wait_password = State()    # только для ветки «пароль»; не логируется, не хранится
    confirm = State()
