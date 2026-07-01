"""Тесты подписанных токенов доступа к дашборду (web/auth.py)."""
from __future__ import annotations

from web.auth import make_token, verify_token

_S = "secret"


def test_roundtrip_returns_tg_id():
    token = make_token(12345, _S)
    assert verify_token(token, _S) == 12345


def test_rejects_wrong_secret():
    token = make_token(1, _S)
    assert verify_token(token, "other") is None


def test_rejects_tampered_body():
    token = make_token(1, _S)
    body, sig = token.rsplit(".", 1)
    assert verify_token(f"{body}x.{sig}", _S) is None


def test_rejects_expired():
    # Выдаём с now в прошлом так, чтобы срок уже истёк.
    token = make_token(1, _S, ttl_sec=10, now=0)
    assert verify_token(token, _S, now=1000) is None


def test_valid_before_expiry():
    token = make_token(7, _S, ttl_sec=100, now=0)
    assert verify_token(token, _S, now=50) == 7


def test_empty_secret_is_none():
    assert verify_token(make_token(1, _S), "") is None


def test_garbage_is_none():
    assert verify_token("not-a-token", _S) is None
    assert verify_token("", _S) is None
