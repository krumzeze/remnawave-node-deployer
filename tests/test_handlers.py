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


@pytest.mark.parametrize(
    "inbounds, expected",
    [
        (None, True),                                  # «все» — дефолт с Reality
        ([], True),
        ([InboundChoice.VLESS_REALITY_TCP.value], True),
        ([InboundChoice.VLESS_GRPC_REALITY.value], True),
        ([InboundChoice.SHADOWSOCKS.value], False),    # SS не Reality
        ([InboundChoice.VLESS_XHTTP_TLS.value], False),  # TLS не Reality
        ([InboundChoice.SHADOWSOCKS.value,
          InboundChoice.VLESS_REALITY_TCP.value], True),  # хотя бы один Reality
    ],
)
def test_selection_has_reality(inbounds, expected):
    assert handlers.selection_has_reality(inbounds) is expected


@pytest.mark.parametrize(
    "text",
    ["", "default", "дефолт", "по умолчанию", "-", "  DEFAULT  "],
)
def test_parse_reality_donor_default(text):
    assert handlers.parse_reality_donor(text) is None


@pytest.mark.parametrize(
    "text, dest, names",
    [
        ("www.cloudflare.com", "www.cloudflare.com:443", ["www.cloudflare.com"]),
        ("www.microsoft.com:443", "www.microsoft.com:443", ["www.microsoft.com"]),
        ("https://example.com/path", "example.com:443", ["example.com"]),
        ("EXAMPLE.COM", "example.com:443", ["example.com"]),
        ("dl.google.com:8443", "dl.google.com:8443", ["dl.google.com"]),
    ],
)
def test_parse_reality_donor_host(text, dest, names):
    assert handlers.parse_reality_donor(text) == (dest, names)


@pytest.mark.parametrize("text", ["not a domain", "localhost", "host:notaport"])
def test_parse_reality_donor_invalid_raises(text):
    with pytest.raises(ValueError):
        handlers.parse_reality_donor(text)


@pytest.mark.parametrize(
    "text, expected",
    [("", None), ("skip", None), ("пропустить", None), ("-", None),
     ("nl", "NL"), ("DE", "DE"), ("  us  ", "US")],
)
def test_parse_country_code_ok(text, expected):
    assert handlers.parse_country_code(text) == expected


@pytest.mark.parametrize("text", ["n", "nld", "n1", "12", "россия"])
def test_parse_country_code_invalid_raises(text):
    with pytest.raises(ValueError):
        handlers.parse_country_code(text)


def test_build_payload_carries_reality_donor_and_country():
    data = {
        "panel_mode": "existing",
        "panel_url": "https://p",
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "key",
        "private_key": "PRIVKEY",
        "inbounds": None,
        "reality_dest": "www.cloudflare.com:443",
        "reality_server_names": ["www.cloudflare.com"],
        "country_code": "NL",
    }
    payload = handlers.build_payload(data, node_id=1, chat_id=1)
    assert payload["reality_dest"] == "www.cloudflare.com:443"
    assert payload["reality_server_names"] == ["www.cloudflare.com"]
    assert payload["country_code"] == "NL"


def test_build_payload_omits_reality_donor_and_country_when_absent():
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
    # Не задано → в payload не кладём, воркер подставит дефолты (донор/«XX»).
    assert "reality_dest" not in payload
    assert "reality_server_names" not in payload
    assert "country_code" not in payload
