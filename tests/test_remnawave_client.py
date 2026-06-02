"""Тесты RemnawaveClient на фейковом SDK.

Реальный пакет remnawave требует Python 3.12 и сетевой панели, поэтому здесь
подменяется только граница SDK: проверяем маппинг ответов в доменные типы и
сведение флагов панели к состоянию ноды. Построение CreateNodeRequestDto
(ленивый импорт моделей remnawave) подменяется на sentinel.
"""
from __future__ import annotations

import types

import pytest

from orchestrator import remnawave_client as rc
from orchestrator.remnawave_client import NodeConnState, RemnawaveClient


class _FakeNode:
    """Имитация NodeResponseDto: только нужные поля."""

    def __init__(self, *, uuid="u-1", name="node-1", address="1.2.3.4", port=3000,
                 is_connected=False, is_connecting=False, is_disabled=False):
        self.uuid = uuid
        self.name = name
        self.address = address
        self.port = port
        self.is_connected = is_connected
        self.is_connecting = is_connecting
        self.is_disabled = is_disabled


class _FakeNodes:
    def __init__(self, node):
        self._node = node
        self.created_body = None

    async def create_node(self, body):
        self.created_body = body
        return self._node

    async def get_one_node(self, uuid):
        self.requested_uuid = uuid
        return self._node


class _FakeKeygen:
    async def generate_key(self):
        return types.SimpleNamespace(pub_key="PANEL_PUBKEY")


class _FakeProfiles:
    def __init__(self):
        self.created_body = None

    async def get_config_profiles(self):
        inb = [types.SimpleNamespace(uuid="inb-1"), types.SimpleNamespace(uuid="inb-2")]
        prof = types.SimpleNamespace(uuid="prof-1", name="default", inbounds=inb)
        return types.SimpleNamespace(config_profiles=[prof])

    async def create_config_profile(self, body):
        # Панель присваивает inbound'ам uuid'ы и возвращает их с тегами.
        self.created_body = body
        inb = [
            types.SimpleNamespace(uuid="inb-aaa", tag="vless-reality-tcp"),
            types.SimpleNamespace(uuid="inb-bbb", tag="shadowsocks"),
        ]
        return types.SimpleNamespace(uuid="prof-new", name="auto", inbounds=inb)


class _FakeSDK:
    def __init__(self, node):
        self.nodes = _FakeNodes(node)
        self.keygen = _FakeKeygen()
        self.config_profiles = _FakeProfiles()


def _client(node):
    return RemnawaveClient("https://panel.example/", "tok", sdk=_FakeSDK(node))


@pytest.mark.parametrize(
    "flags,expected",
    [
        (dict(is_connected=True), NodeConnState.ONLINE),
        (dict(is_connecting=True), NodeConnState.CONNECTING),
        (dict(is_disabled=True), NodeConnState.DISABLED),
        # Выключенная важнее, чем «подключается».
        (dict(is_disabled=True, is_connecting=True), NodeConnState.DISABLED),
        (dict(), NodeConnState.OFFLINE),
    ],
)
def test_derive_status(flags, expected):
    assert rc._derive_status(_FakeNode(**flags)) is expected


def test_panel_url_normalized():
    c = _client(_FakeNode())
    assert c.panel_url == "https://panel.example"


@pytest.mark.asyncio
async def test_get_panel_pubkey():
    c = _client(_FakeNode())
    assert await c.get_panel_pubkey() == "PANEL_PUBKEY"


@pytest.mark.asyncio
async def test_list_config_profiles():
    c = _client(_FakeNode())
    profiles = await c.list_config_profiles()
    assert len(profiles) == 1
    assert profiles[0].uuid == "prof-1"
    assert profiles[0].inbound_uuids == ["inb-1", "inb-2"]


@pytest.mark.asyncio
async def test_create_config_profile_maps_tags(monkeypatch):
    # Подменяем построение DTO, чтобы не тянуть пакет remnawave.
    sentinel = object()
    monkeypatch.setattr(rc, "_build_config_profile_request",
                        lambda *a, **k: sentinel)
    sdk = _FakeSDK(_FakeNode())
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    created = await c.create_config_profile("auto", {"inbounds": []})

    assert sdk.config_profiles.created_body is sentinel
    assert created.uuid == "prof-new"
    assert created.tag_to_inbound == {
        "vless-reality-tcp": "inb-aaa",
        "shadowsocks": "inb-bbb",
    }


@pytest.mark.asyncio
async def test_create_node_maps_response(monkeypatch):
    # Подменяем построение DTO, чтобы не тянуть пакет remnawave.
    sentinel = object()
    monkeypatch.setattr(rc, "_build_create_request",
                        lambda *a, **k: sentinel)
    node = _FakeNode(uuid="abc", port=3000, is_connecting=True)
    sdk = _FakeSDK(node)
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    info = await c.create_node("node-1", "1.2.3.4", "prof-1", ["inb-1"], port=3000)

    assert sdk.nodes.created_body is sentinel
    assert info.uuid == "abc"
    assert info.port == 3000
    assert info.status is NodeConnState.CONNECTING


@pytest.mark.asyncio
async def test_get_node_status_online():
    c = _client(_FakeNode(is_connected=True))
    assert await c.get_node_status("abc") is NodeConnState.ONLINE
