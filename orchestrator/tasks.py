"""Задачи очереди arq и воркер.

Воркер берёт provision_node из Redis и прогоняет state-машину:
bootstrap → ansible (hardening + Docker) → deploy remnanode → CreateNode →
poll до online. Статусы шлются обратно в Telegram/веб.
"""
from __future__ import annotations

import logging

from arq.connections import RedisSettings

from config import settings

logger = logging.getLogger(__name__)


async def provision_node(ctx: dict, payload: dict) -> None:
    """Полный цикл провижининга ноды.

    payload содержит ip/login/auth (+ пароль для ветки password — он живёт
    только здесь и стирается после bootstrap, в БД не пишется).
    """
    # TODO: detect_environment → отбраковать не Ubuntu 22/24 / не KVM
    # TODO: bootstrap (password|key) → ключ в Vault
    # TODO: ansible-runner: hardening.yml + deploy_node.yml
    # TODO: RemnawaveClient.create_node → secret_key/node_port
    # TODO: deploy remnanode compose с secret_key → docker compose up -d
    # TODO: poll get_node_status до online; обновлять state и слать статусы
    # TODO: при сбое — rollback к предыдущему рабочему состоянию
    raise NotImplementedError


class WorkerSettings:
    functions = [provision_node]
    redis_settings = RedisSettings(host=settings.redis_host,
                                   port=settings.redis_port)
