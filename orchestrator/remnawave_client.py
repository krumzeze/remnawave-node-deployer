"""Обёртка над Remnawave API (SDK remnawave 2.7.x).

Работает одинаково для своей панели и для чужой (bring-your-own-panel, ADR 0001):
URL и токен передаются на вызове. Токен берётся из Vault, не из БД.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CreatedNode:
    uuid: str
    secret_key: str
    node_port: int


class RemnawaveClient:
    def __init__(self, panel_url: str, api_token: str) -> None:
        self.panel_url = panel_url.rstrip("/")
        self._token = api_token
        # TODO: init SDK client

    async def create_node(self, name: str, address: str) -> CreatedNode:
        """CreateNode → SECRET_KEY + NODE_PORT для compose remnanode."""
        raise NotImplementedError  # TODO

    async def get_node_status(self, uuid: str) -> str:
        """Статус ноды; поллим до 'online'."""
        raise NotImplementedError  # TODO
