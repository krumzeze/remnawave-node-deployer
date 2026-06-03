"""Обёртка над ansible-runner: инвентарь из SSH-ключа и запуск плейбука.

Плейбуны (`hardening.yml`, `deploy_node.yml`) запускаются по уже переведённому
на ключевую аутентификацию серверу (ADR 0002): сюда приходит приватный ключ,
полученный из bootstrap и лежащий в Vault. Пароль здесь не используется.

`ansible_runner.run` — синхронный, поэтому исполняется в отдельном потоке через
`asyncio.to_thread`, чтобы не блокировать воркер очереди. Сам `run` инъектируется
параметром `runner` — это шов для юнит-тестов: реального ansible и сервера в
тестах нет, проверяется только то, что мы правильно собрали инвентарь и vars.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

# Плейбуны лежат в ansible/playbooks рядом с пакетом orchestrator.
PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "ansible" / "playbooks"
HARDENING_PLAYBOOK = PLAYBOOKS_DIR / "hardening.yml"
DEPLOY_NODE_PLAYBOOK = PLAYBOOKS_DIR / "deploy_node.yml"
ISSUE_CERT_PLAYBOOK = PLAYBOOKS_DIR / "issue_cert.yml"   # TLS-инбаунды, ADR 0005
OPEN_PORTS_PLAYBOOK = PLAYBOOKS_DIR / "open_ports.yml"   # порты inbound'ов в UFW

# Имя хоста в инвентаре. Один сервер на запуск — больше для ноды не нужно.
INVENTORY_HOST = "node"


@dataclass
class PlaybookResult:
    """Итог запуска плейбука."""

    ok: bool
    detail: str = ""
    rc: int | None = None
    status: str | None = None


def _build_inventory(host: str, login: str, port: int) -> str:
    """INI-инвентарь на один хост.

    Питон на ноде берём системный: Ubuntu 22/24 (детекция гарантирует именно их)
    несёт /usr/bin/python3, отдельный интерпретатор поднимать не нужно.
    """
    return (
        f"{INVENTORY_HOST} "
        f"ansible_host={host} "
        f"ansible_user={login} "
        f"ansible_port={port} "
        f"ansible_python_interpreter=/usr/bin/python3\n"
    )


async def run_playbook(
    playbook: str | Path,
    host: str,
    login: str,
    private_key: str,
    *,
    port: int = 22,
    extra_vars: dict[str, Any] | None = None,
    runner: Callable[..., Any] | None = None,
) -> PlaybookResult:
    """Запустить один плейбук по серверу с доступом по приватному ключу.

    `private_key` — PEM нашей per-node пары (после bootstrap, из Vault). Он
    передаётся в ansible-runner как `ssh_key`: тот сам кладёт его во временный
    файл с правами 600 и поднимает ssh-agent на время запуска, на диск проекта
    ключ не пишется.

    Проверку ключа хоста отключаем (`ANSIBLE_HOST_KEY_CHECKING=False`): сервер
    чужой и при первом входе его отпечаток нам неизвестен — та же модель TOFU,
    что и в ssh_bootstrap.
    """
    if runner is None:  # ленивый импорт: тесты обходятся без пакета ansible-runner
        import ansible_runner

        runner = ansible_runner.run

    inventory = _build_inventory(host, login, port)

    def _invoke() -> Any:
        # private_data_dir ansible-runner создаст сам во временной папке.
        return runner(
            playbook=str(playbook),
            inventory=inventory,
            extravars=extra_vars or {},
            ssh_key=private_key,
            host_pattern=INVENTORY_HOST,
            envvars={"ANSIBLE_HOST_KEY_CHECKING": "False"},
            quiet=True,
        )

    result = await asyncio.to_thread(_invoke)

    rc = getattr(result, "rc", None)
    status = getattr(result, "status", None)
    ok = rc == 0 and status == "successful"

    name = Path(str(playbook)).name
    if ok:
        log.info("playbook %s: ok", name)
        return PlaybookResult(ok=True, detail=f"{name}: успешно", rc=rc, status=status)

    log.warning("playbook %s: rc=%s status=%s", name, rc, status)
    return PlaybookResult(
        ok=False,
        detail=f"{name}: ansible завершился со статусом {status!r} (rc={rc})",
        rc=rc,
        status=status,
    )
