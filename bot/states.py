"""FSM-состояния диалога добавления ноды.

Развилка аутентификации (ADR 0002): пользователь выбирает способ доступа —
по паролю (низкий порог) или по публичному ключу / one-liner (выше доверие).
Логин сервера спрашиваем до развилки — он нужен обеим веткам. Обе ветки
сходятся в выбор inbound'ов (ADR 0005) и постановку задачи оркестратору.
"""
from aiogram.fsm.state import State, StatesGroup


class AddNode(StatesGroup):
    # Выбор: подключить существующую панель или развернуть с нуля (ADR 0001)
    choose_panel_mode = State()
    wait_panel_url = State()
    wait_panel_token = State()

    # Данные сервера
    wait_ip = State()
    wait_login = State()       # логин нужен обеим веткам доступа
    choose_auth = State()      # пароль | ключ (ADR 0002)
    wait_password = State()    # только для ветки «пароль»; не логируется, не хранится
    wait_key_added = State()   # ветка «ключ»: ждём, пока оператор добавит наш pubkey

    # Набор inbound'ов профиля (ADR 0005)
    choose_inbounds = State()
    wait_domain = State()      # только если выбран TLS-инбаунд: домен оператора

    confirm = State()
