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
        ("7", [InboundChoice.HYSTERIA2.value]),             # Hysteria2 (доменный)
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
        ([InboundChoice.HYSTERIA2.value], True),    # Hysteria2 — TLS обязателен
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
    payload = handlers.build_payload(
        data, node_id=5, chat_id=42,
        secret_vault_path="transient/nodes/5/bootstrap",
        panel_token_vault_path="panels/7/token",
    )

    assert payload["node_id"] == 5
    assert payload["chat_id"] == 42
    # Секреты в payload не попадают — только пути к ним в Vault. auth остаётся.
    assert "password" not in payload
    assert "private_key" not in payload
    assert "panel_token" not in payload
    assert payload["auth"] == "password"
    assert payload["secret_vault_path"] == "transient/nodes/5/bootstrap"
    assert payload["panel_token_vault_path"] == "panels/7/token"
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
    payload = handlers.build_payload(
        data, node_id=1, chat_id=1,
        secret_vault_path="transient/nodes/1/bootstrap",
        panel_token_vault_path="panels/7/token",
    )

    assert "private_key" not in payload
    assert "password" not in payload
    assert payload["auth"] == "key"
    assert payload["secret_vault_path"] == "transient/nodes/1/bootstrap"
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
    payload = handlers.build_payload(
        data, node_id=1, chat_id=1,
        secret_vault_path="transient/nodes/1/bootstrap",
        panel_token_vault_path="panels/7/token",
    )
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
    payload = handlers.build_payload(
        data, node_id=1, chat_id=1,
        secret_vault_path="transient/nodes/1/bootstrap",
        panel_token_vault_path="panels/7/token",
    )
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
    payload = handlers.build_payload(
        data, node_id=1, chat_id=1,
        secret_vault_path="transient/nodes/1/bootstrap",
        panel_token_vault_path="panels/7/token",
    )
    # Не задано → в payload не кладём, воркер подставит дефолты (донор/«XX»).
    assert "reality_dest" not in payload
    assert "reality_server_names" not in payload
    assert "country_code" not in payload


_SQUAD_OPTIONS = [
    {"uuid": "sq-1", "name": "all"},
    {"uuid": "sq-2", "name": "vip"},
    {"uuid": "sq-3", "name": "trial"},
]


@pytest.mark.parametrize("text", ["", "all", "все", "  ALL  "])
def test_parse_squad_selection_all_means_none(text):
    # «Все» отдаём как None — в payload не кладём, воркер добавит во все сквады.
    assert handlers.parse_squad_selection(text, _SQUAD_OPTIONS) is None


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1", ["sq-1"]),
        ("1 3", ["sq-1", "sq-3"]),
        ("2,1", ["sq-2", "sq-1"]),
        ("2 2 2", ["sq-2"]),            # дубли схлопываются
    ],
)
def test_parse_squad_selection_numbers(text, expected):
    assert handlers.parse_squad_selection(text, _SQUAD_OPTIONS) == expected


@pytest.mark.parametrize("text", ["0", "4", "x", "1 bogus"])
def test_parse_squad_selection_invalid_raises(text):
    with pytest.raises(ValueError):
        handlers.parse_squad_selection(text, _SQUAD_OPTIONS)


def test_build_payload_carries_squad_uuids():
    data = {
        "panel_mode": "existing", "panel_url": "https://p",
        "ip": "1.2.3.4", "login": "root", "auth": "key", "private_key": "K",
        "inbounds": None, "squad_uuids": ["sq-2"],
    }
    payload = handlers.build_payload(
        data, node_id=1, chat_id=1,
        secret_vault_path="transient/nodes/1/bootstrap",
        panel_token_vault_path="panels/7/token",
    )
    assert payload["squad_uuids"] == ["sq-2"]


def test_build_payload_omits_squads_when_absent():
    data = {
        "panel_mode": "existing", "panel_url": "https://p",
        "ip": "1.2.3.4", "login": "root", "auth": "key", "private_key": "K",
        "inbounds": None,
    }
    payload = handlers.build_payload(
        data, node_id=1, chat_id=1,
        secret_vault_path="transient/nodes/1/bootstrap",
        panel_token_vault_path="panels/7/token",
    )
    assert "squad_uuids" not in payload


# --------------------------------------------------------------------------
# Разворот панели с нуля (режим «new», ADR 0001): валидатор пароля админа и
# сборка payload панели. Чистые функции — без сети и FSM.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "password",
    [
        "Abcdefghijklmnopqrstuv1Z",      # ровно 24, есть все классы
        "MyStrongPanelPassword2026!!",   # длиннее, со спецсимволами
    ],
)
def test_validate_admin_password_ok(password):
    assert handlers.validate_admin_password(password) is None


@pytest.mark.parametrize(
    "password",
    [
        "",                              # пусто
        "Short1A",                       # короче 24
        "abcdefghijklmnopqrstuvw1",      # нет заглавной
        "ABCDEFGHIJKLMNOPQRSTUVW1",      # нет строчной
        "Abcdefghijklmnopqrstuvwz",      # нет цифры
    ],
)
def test_validate_admin_password_rejects(password):
    # Возвращается понятный текст ошибки, а не None.
    msg = handlers.validate_admin_password(password)
    assert isinstance(msg, str) and msg


def test_build_panel_payload_vps_omits_raw_secrets():
    data = {
        "panel_mode": "new",
        "placement": "vps",
        "panel_domain": "panel.example",
        "admin_username": "admin",
        "admin_password": "MyStrongPanelPassword2026",
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "password",
        "password": "server-pw",
    }
    payload = handlers.build_panel_payload(
        data, owner=7, chat_id=42,
        admin_secret_vault_path="transient/panels/7/admin",
        secret_vault_path="transient/panels/7/bootstrap",
    )

    assert payload["owner"] == 7
    assert payload["chat_id"] == 42
    assert payload["placement"] == "vps"
    assert payload["panel_domain"] == "panel.example"
    assert payload["admin_username"] == "admin"
    # Сырых секретов в payload нет — только пути в Vault.
    assert "admin_password" not in payload
    assert "password" not in payload
    assert "private_key" not in payload
    assert payload["admin_secret_vault_path"] == "transient/panels/7/admin"
    assert payload["secret_vault_path"] == "transient/panels/7/bootstrap"
    # Для vps есть доступ к серверу.
    assert payload["ip"] == "1.2.3.4"
    assert payload["auth"] == "password"


def test_build_panel_payload_local_has_no_server_access():
    data = {
        "panel_mode": "new",
        "placement": "local",
        "panel_domain": "panel.example",
        "admin_username": "admin",
        "admin_password": "MyStrongPanelPassword2026",
    }
    payload = handlers.build_panel_payload(
        data, owner=7, chat_id=42,
        admin_secret_vault_path="transient/panels/7/admin",
    )

    assert payload["placement"] == "local"
    # Локально сервера нет — ip/login/auth/secret_vault_path не кладём.
    assert "ip" not in payload
    assert "login" not in payload
    assert "auth" not in payload
    assert "secret_vault_path" not in payload
    assert "admin_password" not in payload
    assert payload["admin_secret_vault_path"] == "transient/panels/7/admin"
