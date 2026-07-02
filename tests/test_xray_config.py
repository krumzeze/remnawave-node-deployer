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
    available_choices_for_node,
    base_choice_from_tag,
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
    # reality-tcp — транспорт "raw" (канон Xray/Remnawave; панель по нему
    # опознаёт инбаунд и добавляет flow xtls-rprx-vision), не "tcp".
    assert by_tag["vless-reality-tcp"]["streamSettings"]["network"] == "raw"
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


def test_ws_alpn_http11_only():
    # WebSocket не работает поверх h2: ws-инбаунд обязан объявлять только
    # http/1.1, иначе клиент, отнегошиировав h2, не подключится. Остальным
    # TLS-инбаундам h2 оставляем.
    prof = build_profile(
        [InboundChoice.VLESS_XHTTP_TLS, InboundChoice.TROJAN_WS_TLS],
        tls_domain="vpn.example.com",
        cert_file="/c/fullchain.pem",
        key_file="/c/key.pem",
    )
    by_proto = {i["protocol"]: i for i in prof.config["inbounds"]}
    assert by_proto["trojan"]["streamSettings"]["tlsSettings"]["alpn"] == ["http/1.1"]
    assert by_proto["vless"]["streamSettings"]["tlsSettings"]["alpn"] == [
        "h2", "http/1.1",
    ]


def test_reserved_ports_are_skipped():
    # Повторный провижн: порты существующего профиля исключаются из раздачи —
    # первый инбаунд не садится на занятый 443, а берёт следующий из пула.
    prof = build_profile(
        [InboundChoice.VLESS_REALITY_TCP, InboundChoice.SHADOWSOCKS],
        reserved_ports={443, 8443},
    )
    ports = list(prof.ports.values())
    assert ports == [8444, 2053]


def test_pool_exhaustion_raises_value_error():
    # Все порты пула зарезервированы — понятная ошибка вместо StopIteration.
    from orchestrator.xray_config import FALLBACK_PORTS, PORT_443

    with pytest.raises(ValueError):
        build_profile(
            [InboundChoice.VLESS_REALITY_TCP],
            reserved_ports={PORT_443, *FALLBACK_PORTS},
        )


def test_host_hint_for_existing_inbound_restores_donor_and_domain():
    # Подсказка хоста восстанавливается из инбаунда профиля: sni Reality — его
    # serverNames (кастомный донор), для TLS — домен из tlsSettings.
    from orchestrator.xray_config import host_hint_for_existing_inbound

    reality = {
        "tag": "vless-reality-tcp-1-2-3-4",
        "streamSettings": {
            "security": "reality",
            "realitySettings": {"serverNames": ["www.cloudflare.com"]},
        },
    }
    hint = host_hint_for_existing_inbound(reality)
    assert hint.security == "reality"
    assert hint.sni == "www.cloudflare.com"
    assert hint.fingerprint == "firefox"

    tls = {
        "tag": "vless-xhttp-tls-1-2-3-4",
        "streamSettings": {
            "security": "tls",
            "tlsSettings": {"serverName": "vpn.example.com"},
        },
    }
    hint = host_hint_for_existing_inbound(tls)
    assert hint.security == "tls"
    assert hint.sni == "vpn.example.com"

    # Неопознаваемый тег → None.
    assert host_hint_for_existing_inbound({"tag": "custom"}) is None


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


def test_ports_map_exposed_and_matches_inbounds():
    prof = build_profile([
        InboundChoice.VLESS_REALITY_TCP,
        InboundChoice.SHADOWSOCKS,
    ])
    # Карта tag→port совпадает с портами в самих inbound'ах.
    in_ports = {o["tag"]: o["port"] for o in prof.config["inbounds"]}
    assert prof.ports == in_ports
    # Первый выбранный сел на 443.
    assert prof.ports["vless-reality-tcp"] == 443
    # Только выбранные теги, ничего лишнего.
    assert set(prof.ports) == {"vless-reality-tcp", "shadowsocks"}


def test_ports_map_respects_overrides():
    prof = build_profile(
        [InboundChoice.VLESS_REALITY_TCP, InboundChoice.SHADOWSOCKS],
        port_overrides={InboundChoice.SHADOWSOCKS: 9999},
    )
    assert prof.ports["shadowsocks"] == 9999
    assert prof.ports["vless-reality-tcp"] == 443


def test_host_hints_reality_use_donor_sni_and_firefox():
    prof = build_profile(
        [InboundChoice.VLESS_XHTTP_REALITY],
        reality_dest="www.cloudflare.com:443",
        reality_server_names=("www.cloudflare.com",),
    )
    h = prof.hosts["vless-xhttp-reality"]
    assert h.security == "reality"
    assert h.network == "xhttp"
    assert h.sni == "www.cloudflare.com"   # донор, а не домен ноды
    assert h.path == "/"
    assert h.fingerprint == "firefox"


def test_host_hints_grpc_service_name_as_path():
    prof = build_profile([InboundChoice.VLESS_GRPC_REALITY])
    assert prof.hosts["vless-grpc-reality"].path == "grpc"
    assert prof.hosts["vless-grpc-reality"].network == "grpc"


def test_host_hints_tls_use_node_domain():
    prof = build_profile(
        [InboundChoice.VLESS_XHTTP_TLS],
        tls_domain="vpn.example.com",
        cert_file="/c.pem", key_file="/k.pem",
    )
    h = prof.hosts["vless-xhttp-tls"]
    assert h.security == "tls"
    assert h.sni == "vpn.example.com"
    assert h.fingerprint == "firefox"


def test_host_hints_shadowsocks_no_security():
    prof = build_profile([InboundChoice.SHADOWSOCKS])
    h = prof.hosts["shadowsocks"]
    assert h.security == "none"
    assert h.sni is None
    assert h.fingerprint is None


def test_hysteria2_requires_domain_and_cert():
    # Hysteria2 — доменный инбаунд (TLS обязателен), без домена/cert падает.
    with pytest.raises(ValueError):
        build_profile([InboundChoice.HYSTERIA2])
    with pytest.raises(ValueError):
        build_profile([InboundChoice.HYSTERIA2], tls_domain="vpn.example.com")


def test_hysteria2_inbound_structure():
    prof = build_profile(
        [InboundChoice.HYSTERIA2],
        tls_domain="vpn.example.com",
        cert_file="/c/fullchain.pem",
        key_file="/c/key.pem",
    )
    inb = prof.config["inbounds"][0]
    assert inb["protocol"] == "hysteria"
    assert inb["settings"]["version"] == 2
    assert inb["settings"]["clients"] == []  # пользователей подставляет панель
    ss = inb["streamSettings"]
    assert ss["network"] == "hysteria"
    assert ss["security"] == "tls"
    assert ss["hysteriaSettings"]["version"] == 2
    tls = ss["tlsSettings"]
    assert tls["alpn"] == ["h3"]
    assert tls["serverName"] == "vpn.example.com"
    assert tls["certificates"][0]["certificateFile"] == "/c/fullchain.pem"
    assert tls["certificates"][0]["keyFile"] == "/c/key.pem"
    # Hysteria2 не Reality — ключей быть не должно.
    assert prof.reality_keys == {}


def test_hysteria2_port_marked_udp():
    prof = build_profile(
        [InboundChoice.HYSTERIA2],
        tls_domain="vpn.example.com",
        cert_file="/c/fullchain.pem",
        key_file="/c/key.pem",
    )
    port = prof.ports["hysteria2"]
    assert port in prof.udp_ports, "Hysteria2 (QUIC) должен открываться по UDP"


def test_base_choice_from_tag():
    # Голый тег и тег с per-node суффиксом распознаются в один и тот же пункт.
    assert base_choice_from_tag("shadowsocks") is InboundChoice.SHADOWSOCKS
    assert (base_choice_from_tag("vless-reality-tcp-1-2-3-4")
            is InboundChoice.VLESS_REALITY_TCP)
    assert base_choice_from_tag("hysteria2-94-125-103-122") is InboundChoice.HYSTERIA2
    assert base_choice_from_tag("unknown-tag") is None
    assert base_choice_from_tag("") is None


def test_available_choices_excludes_present():
    # На ноде уже есть reality-tcp и shadowsocks — их в списке добавляемых нет.
    existing = ["vless-reality-tcp-1-2-3-4", "shadowsocks-1-2-3-4"]
    avail = available_choices_for_node(existing, has_domain=False)
    assert InboundChoice.VLESS_REALITY_TCP not in avail
    assert InboundChoice.SHADOWSOCKS not in avail
    # Domain-free reality-варианты доступны.
    assert InboundChoice.VLESS_XHTTP_REALITY in avail
    assert InboundChoice.VLESS_GRPC_REALITY in avail


def test_available_choices_hide_domain_inbounds_without_domain():
    # Без домена доменные инбаунды (TLS/Hysteria2) не предлагаем.
    avail = available_choices_for_node([], has_domain=False)
    assert InboundChoice.HYSTERIA2 not in avail
    assert InboundChoice.VLESS_XHTTP_TLS not in avail
    assert InboundChoice.TROJAN_WS_TLS not in avail


def test_available_choices_offer_domain_inbounds_when_domain_present():
    # У ноды есть доменный инбаунд (значит сертификат выпущен) — Hysteria2 можно.
    existing = ["vless-xhttp-tls-1-2-3-4"]
    avail = available_choices_for_node(existing, has_domain=True)
    assert InboundChoice.HYSTERIA2 in avail
    assert InboundChoice.TROJAN_WS_TLS in avail
    # Уже стоящий tls-xhttp повторно не предлагаем.
    assert InboundChoice.VLESS_XHTTP_TLS not in avail


def test_host_hints_hysteria2_tls_no_fingerprint():
    prof = build_profile(
        [InboundChoice.HYSTERIA2],
        tls_domain="vpn.example.com",
        cert_file="/c/fullchain.pem",
        key_file="/c/key.pem",
    )
    h = prof.hosts["hysteria2"]
    assert h.security == "tls"
    assert h.network == "hysteria"
    assert h.sni == "vpn.example.com"
    assert h.fingerprint is None  # QUIC, uTLS-отпечатка нет
