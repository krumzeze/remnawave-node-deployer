"""Тесты сборки Happ-routing профиля обхода РФ.

Профиль чистый (без SDK): проверяем структуру (РФ — direct, остальное — в
туннель) и формат deeplink (режим onadd + декодируемый base64 JSON)."""
from __future__ import annotations

import base64
import json

from orchestrator.happ_routing import (
    RU_BYPASS_PROFILE,
    build_deeplink,
    build_ru_bypass_deeplink,
)


def test_profile_keeps_ru_direct_and_rest_proxied():
    assert RU_BYPASS_PROFILE["GlobalProxy"] == "true"
    # Охват РФ держится на своей geo-базе (дефолтная Loyalsoldier для РФ пустая)
    # и geosite-кодах: Happ игнорирует правила domain:, geosite:ru ронял ядро.
    assert RU_BYPASS_PROFILE["Geositeurl"].endswith("geosite.dat")
    assert RU_BYPASS_PROFILE["Geoipurl"].endswith("geoip.dat")
    direct = RU_BYPASS_PROFILE["DirectSites"]
    assert "geosite:category-ru" in direct
    assert all(s.startswith(("geosite:", "geoip:")) for s in direct)
    assert not any(s.endswith(":ru") for s in direct)  # geosite:ru роняет ядро
    assert "geoip:private" in RU_BYPASS_PROFILE["DirectIp"]


def test_deeplink_is_onadd_and_decodes_back():
    link = build_ru_bypass_deeplink()
    prefix = "happ://routing/onadd/"
    assert link.startswith(prefix)
    payload = link[len(prefix):]
    decoded = json.loads(base64.b64decode(payload).decode("utf-8"))
    assert decoded == RU_BYPASS_PROFILE


def test_build_deeplink_mode_add():
    link = build_deeplink({"Name": "x"}, mode="add")
    assert link.startswith("happ://routing/add/")
