"""Тесты чистых хелперов хендлеров бота: разбор inbound'ов, нужен ли домен и
сборка payload. Сетевую часть aiogram/arq/БД здесь не трогаем — проверяем
логику, которая формирует задачу для воркера."""
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
        ("1 6", [InboundChoice.VLESS_REALITY_TCP.value, InboundChoice.SHADOWSOCKS.value]),
        ("6,4", [InboundChoice.SHADOWSOCKS.value, InboundChoice.VLESS_GRPC_REALITY.value]),
        ("3", [InboundChoice.VLESS_XHTTP_TLS.value]),       # TLS-пункт
        ("5", [InboundChoice.TROJAN_WS_TLS.value]),         # TLS-пункт
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


@pytest.mark.parametrize(
    "inbounds, expected",
    [
        (None, False),                              # «все» — дефолт domain-free
        ([], False),
        ([InboundChoice.VLESS_REALITY_TCP.value], False),
        ([InboundChoice.SHADOWSOCKS.value], False),
        ([InboundChoice.VLESS_XHTTP_TLS.value], True),
        ([InboundChoice.TROJAN_WS_TLS.value], True),
        ([InboundChoice.VLESS_REALITY_TCP.value,
          InboundChoice.TROJAN_WS_TLS.value], True),  # хотя бы один TLS
    ],
)
def test_selection_needs_domain(inbounds, expected):
    assert handlers.selection_needs_domain(inbounds) is expected


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
    # домена не было — в payload его нет
    assert "tls_domain" not in payload


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


def test_build_payload_carries_tls_domain():
    data = {
        "panel_mode": "existing",
        "panel_url": "https://p",
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "key",
        "private_key": "PRIVKEY",
        "inbounds": [InboundChoice.VLESS_XHTTP_TLS.value],
        "tls_domain": "vpn.example.com",
    }
    payload = handlers.build_payload(data, node_id=1, chat_id=1)
    assert payload["tls_domain"] == "vpn.example.com"
