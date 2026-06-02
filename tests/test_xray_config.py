"""Тесты генератора Xray-конфига (orchestrator/xray_config.py).

Проверяем то, что нельзя вывести из кода глазами: валидность Reality-ключей,
непустоту/уникальность shortIds, корректную структуру каждого inbound по
протоколу/транспорту/security, отбор по выбранным пунктам, обязательность
домена для TLS и раскладку портов без конфликтов.
"""
from __future__ import annotations

import base64

import pytest

from orchestrator.xray_config import (
    DEFAULT_REALITY_DEST,
    InboundChoice,
    REALITY_CHOICES,
    build_profile,
    generate_reality_keys,
)


def _b64url_len(s: str) -> int:
    # Длина исходных байт из base64url без паддинга.
    pad = "=" * (-len(s) % 4)
    return len(base64.urlsafe_b64decode(s + pad))


def test_reality_keys_valid_x25519():
    keys = generate_reality_keys()
    # x25519: и приватный, и публичный ключ — ровно 32 байта.
    assert _b64url_len(keys.private_key) == 32
    assert _b64url_len(keys.public_key) == 32
    assert keys.private_key != keys.public_key


def test_reality_short_ids_nonempty_unique_hex():
    keys = generate_reality_keys()
    assert keys.short_ids, "shortIds не должны быть пустым списком"
    assert len(set(keys.short_ids)) == len(keys.short_ids)
    for sid in keys.short_ids:
        assert sid, "пустой shortId не используем"
        assert len(sid) % 2 == 0 and len(sid) <= 16
        int(sid, 16)  # бросит, если не hex


def test_reality_keys_are_random_between_calls():
    assert generate_reality_keys().private_key != generate_reality_keys().private_key


def test_empty_choices_rejected():
    with pytest.raises(ValueError):
        build_profile([])


def test_full_config_skeleton():
    prof = build_profile([InboundChoice.VLESS_REALITY_TCP])
    cfg = prof.config
    assert cfg["inbounds"], "должен быть хотя бы один inbound"
    tags = {o["tag"] for o in cfg["outbounds"]}
    assert {"direct", "block"} <= tags
    assert "routing" in cfg


def test_selection_is_respected_and_deduped():
    chosen = [
        InboundChoice.VLESS_REALITY_TCP,
        InboundChoice.SHADOWSOCKS,
        InboundChoice.VLESS_REALITY_TCP,  # дубль — должен схлопнуться
    ]
    prof = build_profile(chosen)
    assert prof.tags == [
        InboundChoice.VLESS_REALITY_TCP.value,
        InboundChoice.SHADOWSOCKS.value,
    ]


def test_reality_inbounds_have_keys_and_settings():
    reality = list(REALITY_CHOICES)
    prof = build_profile(reality)
    by_tag = {o["tag"]: o for o in prof.config["inbounds"]}
    for choice in reality:
        inb = by_tag[choice.value]
        rs = inb["streamSettings"]["realitySettings"]
        assert inb["streamSettings"]["security"] == "reality"
        assert rs["dest"] == DEFAULT_REALITY_DEST
        assert rs["privateKey"]
        assert rs["shortIds"]
        # ключи для каждого Reality-inbound'а уникальны
        assert choice.value in prof.reality_keys
    privs = {k.private_key for k in prof.reality_keys.values()}
    assert len(privs) == len(reality), "у каждого inbound своя пара ключей"


def test_transport_mapping():
    prof = build_profile([
        InboundChoice.VLESS_REALITY_TCP,
        InboundChoice.VLESS_XHTTP_REALITY,
        InboundChoice.VLESS_GRPC_REALITY,
    ])
    by_tag = {o["tag"]: o for o in prof.config["inbounds"]}
    assert by_tag["vless-reality-tcp"]["streamSettings"]["network"] == "tcp"
    assert by_tag["vless-xhttp-reality"]["streamSettings"]["network"] == "xhttp"
    assert by_tag["vless-grpc-reality"]["streamSettings"]["network"] == "grpc"


def test_tls_requires_domain_and_cert():
    with pytest.raises(ValueError):
        build_profile([InboundChoice.VLESS_XHTTP_TLS])
    with pytest.raises(ValueError):
        build_profile([InboundChoice.TROJAN_WS_TLS], tls_domain="vpn.example.com")


def test_tls_inbound_uses_domain_and_cert_paths():
    prof = build_profile(
        [InboundChoice.VLESS_XHTTP_TLS, InboundChoice.TROJAN_WS_TLS],
        tls_domain="vpn.example.com",
        cert_file="/c/fullchain.pem",
        key_file="/c/key.pem",
    )
    for inb in prof.config["inbounds"]:
        tls = inb["streamSettings"]["tlsSettings"]
        assert inb["streamSettings"]["security"] == "tls"
        assert tls["serverName"] == "vpn.example.com"
        assert tls["certificates"][0]["certificateFile"] == "/c/fullchain.pem"
        assert tls["certificates"][0]["keyFile"] == "/c/key.pem"
    # никаких Reality-ключей в чисто TLS-наборе
    assert prof.reality_keys == {}


def test_shadowsocks_method_and_password():
    prof = build_profile([InboundChoice.SHADOWSOCKS])
    inb = prof.config["inbounds"][0]
    assert inb["protocol"] == "shadowsocks"
    s = inb["settings"]
    assert s["method"] == "2022-blake3-aes-256-gcm"
    assert _b64url_len(base64.b64encode(base64.b64decode(s["password"])).decode()) == 32


def test_port_layout_no_conflicts_first_gets_443():
    all_choices = list(InboundChoice)
    prof = build_profile(
        all_choices,
        tls_domain="vpn.example.com",
        cert_file="/c/fullchain.pem",
        key_file="/c/key.pem",
    )
    ports = [o["port"] for o in prof.config["inbounds"]]
    assert ports[0] == 443, "первый выбранный должен сесть на 443"
    assert len(ports) == len(set(ports)), "порты не должны конфликтовать"


def test_port_overrides_respected():
    prof = build_profile(
        [InboundChoice.VLESS_REALITY_TCP, InboundChoice.SHADOWSOCKS],
        port_overrides={InboundChoice.SHADOWSOCKS: 9999},
    )
    by_tag = {o["tag"]: o for o in prof.config["inbounds"]}
    assert by_tag["shadowsocks"]["port"] == 9999
    assert by_tag["vless-reality-tcp"]["port"] == 443


def test_no_clients_injected():
    prof = build_profile(list(REALITY_CHOICES))
    for inb in prof.config["inbounds"]:
        # пользователей панель подставляет сама — список клиентов пуст
        assert inb["settings"].get("clients") == []
