"""SSH-действия над уже развёрнутой нодой (ADR 0013).

Перезапуск контейнера remnanode (лёгкая первая попытка) и перезагрузка сервера
(для забитой памяти — контейнер вернётся сам: restart: always + docker в
автозапуске). Подключаемся по приватному ключу ноды из Vault. Доступно только
нодам, у которых ключ есть (свои и удочерённые); импортированными без ключа
управлять нельзя.

Если подключиться не удалось, отдаём это отдельным понятным сообщением —
обычно это значит, что сервер действительно лёг и достучаться по SSH не выходит.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import asyncssh

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 15
# Имя контейнера ноды задаётся в compose-шаблоне (container_name: remnanode),
# поэтому restart адресуется по нему, а не по сгенерированному имени compose.
NODE_CONTAINER = "remnanode"
# reboot рвёт SSH-сессию. Запускаем его в фоне с маленькой задержкой, чтобы
# сама команда успела вернуть код 0 и сессия закрылась штатно, а перезагрузка
# началась уже после нашего отключения.
_REBOOT_CMD = "nohup sh -c 'sleep 1; reboot' >/dev/null 2>&1 &"
_OUT_MAX = 300


@dataclass
class OpResult:
    ok: bool
    detail: str


async def _connect_run(
    ip: str, login: str, private_key: str, command: str, *, port: int = 22
) -> OpResult:
    """Подключиться по ключу и выполнить команду.

    Сбой именно подключения отделяем от сбоя команды: первое почти всегда
    значит «сервер недоступен» (лёг по памяти/сети), и сообщение об этом для
    оператора важнее, чем текст исключения."""
    try:
        conn = await asyncssh.connect(
            ip,
            port=port,
            username=login,
            client_keys=[asyncssh.import_private_key(private_key)],
            known_hosts=None,
            connect_timeout=CONNECT_TIMEOUT,
        )
    except (OSError, asyncssh.Error) as exc:
        logger.warning("node_ops: не подключиться к %s: %s", ip, exc)
        return OpResult(
            ok=False,
            detail="Сервер скорее всего недоступен — достучаться по SSH не вышло.",
        )
    try:
        res = await conn.run(command, check=False)
    except (OSError, asyncssh.Error) as exc:
        return OpResult(ok=False, detail=f"Команда не выполнилась: {exc}")
    finally:
        conn.close()

    if res.exit_status != 0:
        detail = (res.stderr or "").strip()[:_OUT_MAX]
        return OpResult(ok=False, detail=detail or f"команда вернула код {res.exit_status}")
    return OpResult(ok=True, detail=(res.stdout or "").strip()[:_OUT_MAX])


async def restart_node(
    ip: str, login: str, private_key: str, *, port: int = 22
) -> OpResult:
    """Перезапустить контейнер remnanode — лёгкая первая попытка лечения."""
    res = await _connect_run(
        ip, login, private_key, f"docker restart {NODE_CONTAINER}", port=port
    )
    if res.ok:
        return OpResult(ok=True, detail="Контейнер ноды перезапущен.")
    return res


async def reboot_server(
    ip: str, login: str, private_key: str, *, port: int = 22
) -> OpResult:
    """Перезагрузить сервер целиком — когда забита память и рестарт не спасает."""
    res = await _connect_run(ip, login, private_key, _REBOOT_CMD, port=port)
    if res.ok:
        return OpResult(
            ok=True,
            detail="Команда на перезагрузку отправлена. Нода вернётся сама "
            "через пару минут (статус обновит поллер).",
        )
    return res
