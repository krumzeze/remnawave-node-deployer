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

import logging
from dataclasses import dataclass

import asyncssh

log = logging.getLogger(__name__)

# Что поддерживает MVP (см. index.md «зоопарк серверов» и отбраковку до изменений).
SUPPORTED_OS_ID = "ubuntu"
SUPPORTED_VERSIONS = {"22.04", "24.04"}
# systemd-detect-virt для контейнерной виртуализации; такие ноды отбраковываем.
REJECTED_VIRT = {"openvz", "lxc", "lxc-libvirt", "docker", "container-other"}

# Время на установление SSH-соединения, сек.
CONNECT_TIMEOUT = 30


@dataclass
class BootstrapResult:
    ok: bool
    private_key: str | None = None   # → сразу в Vault, не в БД
    detail: str = ""


@dataclass
class Environment:
    """Сырой снимок окружения сервера, снятый ДО любых изменений."""
    os_id: str
    os_version: str
    virt: str
    kernel: str


def _evaluate_environment(env: Environment) -> tuple[bool, str]:
    """Чистая функция-проверка: подходит ли сервер для MVP.

    Вынесена отдельно от SSH, чтобы тестировать без реального сервера.
    Возвращает (ok, человекочитаемая причина отказа|"").
    """
    if env.os_id != SUPPORTED_OS_ID:
        return False, (
            f"ОС «{env.os_id}» не поддерживается. MVP работает только с "
            f"Ubuntu {'/'.join(sorted(SUPPORTED_VERSIONS))}."
        )
    if env.os_version not in SUPPORTED_VERSIONS:
        return False, (
            f"Ubuntu {env.os_version} не поддерживается. Нужна версия "
            f"{' или '.join(sorted(SUPPORTED_VERSIONS))}."
        )
    if env.virt in REJECTED_VIRT:
        return False, (
            f"Виртуализация «{env.virt}» (контейнер) не поддерживается: "
            f"нет доступа к сетевому стеку и модулям ядра, нужным ноде. "
            f"Подходит KVM или железный сервер."
        )
    return True, ""


def _generate_keypair() -> tuple[str, str]:
    """Генерит per-node ed25519-ключ. Возвращает (private_openssh, public_openssh)."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    private_pem = key.export_private_key().decode()
    public_line = key.export_public_key().decode().strip()
    return private_pem, public_line


async def _read_environment(conn: asyncssh.SSHClientConnection) -> Environment:
    """Снимает окружение по уже открытому соединению (без изменений на сервере)."""
    os_release = (await conn.run("cat /etc/os-release", check=False)).stdout or ""
    fields: dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip().strip('"')

    virt = ((await conn.run("systemd-detect-virt", check=False)).stdout or "").strip()
    kernel = ((await conn.run("uname -r", check=False)).stdout or "").strip()

    return Environment(
        os_id=fields.get("ID", "").lower(),
        os_version=fields.get("VERSION_ID", ""),
        virt=virt or "unknown",
        kernel=kernel,
    )


async def detect_environment(
    host: str,
    login: str,
    *,
    password: str | None = None,
    private_key: str | None = None,
    port: int = 22,
) -> tuple[bool, Environment | None, str]:
    """Детекция окружения ДО изменений: ОС, версия, тип виртуализации, ядро.

    Подключается по паролю ИЛИ по ключу (что передано), снимает окружение,
    прогоняет через `_evaluate_environment`. Ничего на сервере не меняет.
    Возвращает (ok, Environment|None, причина_отказа|"").
    """
    client_keys = [asyncssh.import_private_key(private_key)] if private_key else None
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=login,
            password=password,
            client_keys=client_keys,
            known_hosts=None,  # TOFU: чужой сервер, доверяем ключу хоста при первом входе
            connect_timeout=CONNECT_TIMEOUT,
        ) as conn:
            env = await _read_environment(conn)
    except (OSError, asyncssh.Error) as exc:
        return False, None, f"Не удалось подключиться к {host}: {exc}"

    ok, reason = _evaluate_environment(env)
    return ok, env, reason


async def _install_and_verify_key(
    conn: asyncssh.SSHClientConnection,
    host: str,
    login: str,
    port: int,
    public_key: str,
    private_key: str,
) -> tuple[bool, str]:
    """Кладёт pubkey в authorized_keys и проверяет вход НОВЫМ соединением по ключу.

    Возврат (ok, detail). Сам по себе ничего необратимого не делает: парольный
    вход здесь ещё не трогаем (см. ADR 0002 — отключаем только после проверки).
    """
    # Идемпотентно: создаём ~/.ssh с правами и дописываем ключ, если его там нет.
    setup_cmd = (
        "set -e; "
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh; "
        "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys; "
        f"grep -qxF '{public_key}' ~/.ssh/authorized_keys "
        f"|| echo '{public_key}' >> ~/.ssh/authorized_keys"
    )
    res = await conn.run(setup_cmd, check=False)
    if res.exit_status != 0:
        return False, f"Не удалось установить публичный ключ: {res.stderr}"

    # Проверка: отдельное соединение ТОЛЬКО по ключу, без пароля.
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=login,
            client_keys=[asyncssh.import_private_key(private_key)],
            password=None,
            known_hosts=None,
            connect_timeout=CONNECT_TIMEOUT,
        ) as verify_conn:
            who = (await verify_conn.run("whoami", check=False)).stdout or ""
            if who.strip() != login:
                return False, "Вход по ключу прошёл, но whoami не совпал с логином."
    except (OSError, asyncssh.Error) as exc:
        return False, f"Вход по новому ключу не работает, пароль не трогаем: {exc}"

    return True, "Вход по ключу подтверждён."


async def bootstrap_password(
    host: str, login: str, password: str, *, port: int = 22
) -> BootstrapResult:
    """Ветка «пароль»: подключиться, выложить ключ, проверить вход по нему.

    По решению оператора (ADR 0002) парольный вход на сервере НЕ отключаем —
    деплойер лишь добавляет свой ключ для безпарольной работы, а жёсткий
    hardening доступа остаётся заботой владельца сервера. Пароль используется
    один раз и удаляется из памяти в конце; в результат он не попадает.
    """
    # 1. Детекция и отбраковка ДО изменений.
    ok, env, reason = await detect_environment(
        host, login, password=password, port=port
    )
    if not ok:
        return BootstrapResult(ok=False, detail=reason or "Окружение не подходит.")
    log.info("env ok: Ubuntu %s, virt=%s", env.os_version, env.virt)

    private_key, public_key = _generate_keypair()

    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=login,
            password=password,
            known_hosts=None,
            connect_timeout=CONNECT_TIMEOUT,
        ) as conn:
            # 2-3. Положить ключ и проверить вход по нему.
            ok, detail = await _install_and_verify_key(
                conn, host, login, port, public_key, private_key
            )
            if not ok:
                # Откат не нужен: пароль ещё работает, ключ просто лишний.
                return BootstrapResult(ok=False, detail=detail)
    except (OSError, asyncssh.Error) as exc:
        return BootstrapResult(ok=False, detail=f"Сбой bootstrap: {exc}")
    finally:
        # 5. Стереть пароль из памяти. Python-строки иммутабельны — гарантированного
        # обнуления буфера нет, но снимаем последнюю ссылку как можно раньше.
        del password

    return BootstrapResult(
        ok=True, private_key=private_key, detail="Ключ добавлен, вход по ключу работает."
    )


async def bootstrap_key(
    host: str, login: str, private_key: str, *, port: int = 22
) -> BootstrapResult:
    """Ветка «ключ»: пользователь сам добавил наш pubkey (one-liner).

    Приватную часть сгенерённой нами пары передаёт хэндлер бота. Здесь пароля
    нет вообще — только проверяем, что вход по ключу работает, и снимаем
    окружение. Отключать парольный вход не наша задача: доступ пользователя по
    его собственным средствам мы не трогаем.
    """
    ok, env, reason = await detect_environment(
        host, login, private_key=private_key, port=port
    )
    if not ok:
        return BootstrapResult(ok=False, detail=reason or "Окружение не подходит.")
    log.info("env ok (key branch): Ubuntu %s, virt=%s", env.os_version, env.virt)

    return BootstrapResult(
        ok=True, private_key=private_key, detail="Доступ по ключу подтверждён."
    )
