"""Тесты валидации ввода перед SSH/ansible (bot/validate.py)."""
from __future__ import annotations

from bot.validate import valid_ipv4, valid_login


def test_valid_ipv4_accepts_addresses():
    assert valid_ipv4("203.0.113.10")
    assert valid_ipv4(" 8.8.8.8 ")


def test_valid_ipv4_rejects_junk():
    for bad in ("", "not-an-ip", "999.1.1.1", "1.2.3", "example.com",
                "2001:db8::1", "1.2.3.4; rm -rf /"):
        assert not valid_ipv4(bad), bad


def test_valid_login_accepts_posix_names():
    for ok in ("root", "deploy", "user_1", "a-b", "_svc"):
        assert valid_login(ok), ok


def test_valid_login_rejects_metacharacters():
    for bad in ("", "1user", "ro ot", "root;reboot", "a$b", "user`id`",
                "-x", "a" * 33):
        assert not valid_login(bad), bad
