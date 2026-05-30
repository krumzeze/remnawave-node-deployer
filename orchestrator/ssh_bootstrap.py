"""Первое подключение к серверу и перевод на ключевую аутентификацию.

ADR 0002, принцип «не навреди»:
  1. подключиться (по паролю или по уже добавленному pubkey);
  2. сгенерить per-node keypair, положить pubkey в authorized_keys;
  3. ПРОВЕРИТЬ, что вход по ключу реально работает;
  4. только теперь отключить парольный вход;
  5. стереть пароль из памяти.

Пароль нигде не сохраняется: ни в БД, ни в логах, ни в payload после bootstrap.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BootstrapResult:
    ok: bool
    private_key: str | None = None   # → сразу в Vault, не в БД
    detail: str = ""


async def detect_environment(host: str, **kwargs) -> dict:  # noqa: D401
    """Детекция окружения ДО изменений: KVM vs OpenVZ, ОС, ядро.

    MVP поддерживает только Ubuntu 22.04/24.04 на KVM — иначе отбраковка
    с понятным сообщением (см. PROJECT.md «зоопарк серверов»).
    """
    raise NotImplementedError  # TODO


async def bootstrap_password(host: str, login: str, password: str) -> BootstrapResult:
    """Ветка «пароль»: подключиться, выложить ключ, проверить, отключить пароль."""
    raise NotImplementedError  # TODO: asyncssh connect → keygen → verify → harden


async def bootstrap_key(host: str, login: str) -> BootstrapResult:
    """Ветка «ключ»: пользователь сам добавил наш pubkey (one-liner)."""
    raise NotImplementedError  # TODO
