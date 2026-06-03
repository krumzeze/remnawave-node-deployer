"""Тесты чистых хелперов хендлеров бота: разбор inbound'ов и сборка payload.

Сетевую часть aiogram/arq/БД здесь не трогаем — проверяем логику, которая
формирует задачу для воркера.
"""
from __future__ import annotations

import pytest

from bot import handlers
from orchestrator.xray_config import InboundChoice


@pytest.mark.parametrize(
    "text, expected",
    [
        ("", None),
        ("all", None),
        ("все", None),
        ("1", [InboundChoice.VLESS_REALITY_TCP.value]),
        ("1 4", [InboundChoice.VLESS_REALITY_TCP.value, InboundChoice.SHADOWSOCKS.value]),
        ("4,3", [InboundChoice.SHADOWSOCKS.value, InboundChoice.VLESS_GRPC_REALITY.value]),
        ("1 1 1", [InboundChoice.VLESS_REALITY_TCP.value]),  # дубли схлопываются
    ],
)
def test_parse_inbounds_ok(text, expected):
    assert handlers.parse_inbounds(text) == expected


def test_parse_inbounds_unknown_raises():
    with pytest.raises(ValueError):
        handlers.parse_inbounds("9")
    with pytest.raises(ValueError):
        handlers.parse_inbounds("1 bogus")


def test_build_payload_password_branch():
    data = {
        "panel_mode": "existing",
        "panel_url": "https://p",
        "panel_token": "tok",
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "password",
        "password": "secret",
        "inbounds": ["shadowsocks"],
    }
    payload = handlers.build_payload(data, node_id=5, chat_id=42)

    assert payload["node_id"] == 5
    assert payload["chat_id"] == 42
    assert payload["password"] == "secret"
    assert "private_key" not in payload
    assert payload["panel_url"] == "https://p"
    assert payload["inbounds"] == ["shadowsocks"]


def test_build_payload_key_branch_omits_password():
    data = {
        "panel_mode": "existing",
        "panel_url": "https://p",
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "key",
        "private_key": "PRIVKEY",
        "inbounds": None,
    }
    payload = handlers.build_payload(data, node_id=1, chat_id=1)

    assert payload["private_key"] == "PRIVKEY"
    assert "password" not in payload
    # inbounds=None (все) в payload не кладём — воркер подставит дефолт.
    assert "inbounds" not in payload
