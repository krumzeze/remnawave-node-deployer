"""Интеграция с HashiCorp Vault (KV v2).

Здесь живут per-node SSH-ключи и токены панелей. В БД хранится только путь
(vault_path), сам секрет — никогда. Это и есть граница изоляции тенантов.
"""
from __future__ import annotations

import hvac

from config import settings


class VaultStore:
    def __init__(self) -> None:
        self._client = hvac.Client(url=settings.vault_addr, token=settings.vault_token)
        self._mount = settings.vault_kv_mount

    def put(self, path: str, data: dict) -> str:
        self._client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=data, mount_point=self._mount
        )
        return path

    def get(self, path: str) -> dict:
        resp = self._client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=self._mount
        )
        return resp["data"]["data"]

    # TODO: ротация per-node ключей; политики доступа на тенанта
