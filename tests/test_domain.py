"""Тесты гейта домена перед выпуском TLS-сертификата (orchestrator/domain.py).

Резолвер инъектируется фейком — в сеть не ходим. Проверяем нормализацию,
валидацию формата и три исхода проверки: совпало, не туда, не резолвится.
"""
from __future__ import annotations

import pytest

from orchestrator import domain


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("  VPN.Example.COM ", "vpn.example.com"),
        ("https://vpn.example.com/", "vpn.example.com"),
        ("http://vpn.example.com", "vpn.example.com"),
        ("vpn.example.com.", "vpn.example.com"),        # FQDN с точкой
        ("vpn.example.com/path/x", "vpn.example.com"),  # вставили URL целиком
    ],
)
def test_normalize_domain(raw, expected):
    assert domain.normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "name, ok",
    [
        ("vpn.example.com", True),
        ("a.b.c.example.io", True),
        ("example", False),          # без TLD
        ("-bad.example.com", False), # метка не может начинаться с дефиса
        ("ba_d.example.com", False), # подчёркивание не допускаем
        ("", False),
    ],
)
def test_is_valid_domain(name, ok):
    assert domain.is_valid_domain(name) is ok


def _resolver(records):
    async def resolve(_domain):
        return list(records)
    return resolve


@pytest.mark.asyncio
async def test_check_points_to_match():
    check = await domain.check_points_to(
        "vpn.example.com", "1.2.3.4", resolver=_resolver(["1.2.3.4"])
    )
    assert check.ok is True
    assert "1.2.3.4" in check.resolved


@pytest.mark.asyncio
async def test_check_points_to_mismatch():
    check = await domain.check_points_to(
        "vpn.example.com", "1.2.3.4", resolver=_resolver(["9.9.9.9"])
    )
    assert check.ok is False
    assert "9.9.9.9" in check.detail


@pytest.mark.asyncio
async def test_check_points_to_no_records():
    check = await domain.check_points_to(
        "vpn.example.com", "1.2.3.4", resolver=_resolver([])
    )
    assert check.ok is False
    assert "не резолвится" in check.detail


@pytest.mark.asyncio
async def test_check_points_to_invalid_domain_skips_dns():
    called = False

    async def resolve(_domain):
        nonlocal called
        called = True
        return ["1.2.3.4"]

    check = await domain.check_points_to("not_a_domain", "1.2.3.4", resolver=resolve)
    assert check.ok is False
    assert called is False  # плохой формат до DNS не доводим
