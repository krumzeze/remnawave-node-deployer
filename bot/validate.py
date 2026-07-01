"""Валидация пользовательского ввода перед уходом в SSH/ansible (ADR 0014).

IP и SSH-логин попадают в команды подключения и в extra-vars плейбуков, а IP ещё
и в теги/адреса хостов панели. Публичный бот принимает их от кого угодно,
поэтому фильтруем строго на входе: IP — только корректный IPv4 (на нём же
построена логика per-node тегов ip.replace('.', '-')), логин — POSIX-имя без
метасимволов оболочки.
"""
from __future__ import annotations

import ipaddress
import re

# POSIX-совместимое имя пользователя: начинается с буквы/подчёркивания, дальше
# буквы/цифры/подчёркивание/дефис. Без пробелов, кавычек, $, ;, & и прочего, чем
# можно было бы вырваться в команду. Длину ограничиваем 32 (лимит useradd).
_LOGIN_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def valid_ipv4(value: str) -> bool:
    """True, если строка — корректный IPv4-адрес."""
    try:
        return isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def valid_login(value: str) -> bool:
    """True, если строка — безопасный POSIX-логин."""
    return bool(_LOGIN_RE.match(value.strip()))
