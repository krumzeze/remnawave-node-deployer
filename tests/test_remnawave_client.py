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


class _FakeHosts:
    def __init__(self, hosts_resp=None):
        self.created_body = None
        # Ответ get_all_hosts; по умолчанию один хост, привязанный к инбаунду
        # через вложенный inbound (форма как у SDK 2.7.x).
        if hosts_resp is None:
            hosts_resp = types.SimpleNamespace(
                hosts=[
                    types.SimpleNamespace(
                        uuid="host-1", remark="NL-01",
                        address="node.example", port=443,
                        inbound=types.SimpleNamespace(
                            config_profile_inbound_uuid="inb-1"
                        ),
                    )
                ]
            )
        self._hosts_resp = hosts_resp

    async def create_host(self, body):
        self.created_body = body
        return types.SimpleNamespace(
            uuid="host-1", remark="NL-01", address="node.example", port=443
        )

    async def get_all_hosts(self):
        return self._hosts_resp


class _FakeSquads:
    def __init__(self):
        self.updated = []
        self._squads = [
            types.SimpleNamespace(
                uuid="sq-1", name="all",
                inbounds=[types.SimpleNamespace(uuid="inb-x")],
            ),
            types.SimpleNamespace(uuid="sq-2", name="vip", inbounds=[]),
        ]

    async def get_internal_squads(self):
        return types.SimpleNamespace(internal_squads=self._squads)

    async def update_internal_squad(self, body):
        self.updated.append(body)
        return types.SimpleNamespace()


class _FakeSubSettings:
    def __init__(self, happ_routing=None):
        self.updated_body = None
        self._happ_routing = happ_routing

    async def get_subscription_settings(self):
        return types.SimpleNamespace(uuid="sub-1", happ_routing=self._happ_routing)

    async def update_subscription_settings(self, body):
        self.updated_body = body
        return types.SimpleNamespace()


class _FakeSDK:
    def __init__(self, node, hosts=None):
        self.nodes = _FakeNodes(node)
        self.keygen = _FakeKeygen()
        self.config_profiles = _FakeProfiles()
        self.hosts = hosts if hosts is not None else _FakeHosts()
        self.internal_squads = _FakeSquads()
        self.subscriptions_settings = _FakeSubSettings()


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


@pytest.mark.asyncio
async def test_create_host_maps_response(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(rc, "_build_create_host_request", lambda **k: sentinel)
    sdk = _FakeSDK(_FakeNode())
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    host = await c.create_host(
        inbound_uuid="inb-1", config_profile_uuid="prof-1",
        remark="NL-01", address="node.example", port=443, security="reality",
    )

    assert sdk.hosts.created_body is sentinel
    assert host.uuid == "host-1"
    assert host.address == "node.example"
    assert host.port == 443


@pytest.mark.asyncio
async def test_list_hosts_maps_response():
    # Нормальный ответ: маппинг полей + uuid инбаунда из вложенного inbound.
    c = _client(_FakeNode())
    hosts = await c.list_hosts()
    assert len(hosts) == 1
    h = hosts[0]
    assert h.uuid == "host-1"
    assert h.remark == "NL-01"
    assert h.address == "node.example"
    assert h.port == 443
    assert h.inbound_uuid == "inb-1"


@pytest.mark.asyncio
async def test_list_hosts_reads_inbound_uuid_from_flat_field():
    # uuid инбаунда лежит прямо в host'е, без вложенного inbound.
    resp = types.SimpleNamespace(hosts=[
        types.SimpleNamespace(
            uuid="host-2", remark="DE", address="2.2.2.2", port=8443,
            inbound_uuid="inb-flat",
        )
    ])
    sdk = _FakeSDK(_FakeNode(), hosts=_FakeHosts(hosts_resp=resp))
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    hosts = await c.list_hosts()
    assert hosts[0].inbound_uuid == "inb-flat"


@pytest.mark.asyncio
async def test_list_hosts_accepts_bare_list():
    # Ответ — голый список (без обёртки .hosts); inbound_uuid недоступен → None.
    resp = [types.SimpleNamespace(
        uuid="host-3", remark="FR", address="3.3.3.3", port=2053
    )]
    sdk = _FakeSDK(_FakeNode(), hosts=_FakeHosts(hosts_resp=resp))
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    hosts = await c.list_hosts()
    assert len(hosts) == 1
    assert hosts[0].address == "3.3.3.3"
    assert hosts[0].inbound_uuid is None


@pytest.mark.asyncio
async def test_list_hosts_missing_method_returns_empty():
    # У SDK нет get_all_hosts → защитный фолбэк: пустой список. Подменяем hosts
    # на объект без этого метода (как у более старой/иной версии SDK).
    sdk = _FakeSDK(_FakeNode())
    sdk.hosts = types.SimpleNamespace(create_host=None)
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    assert await c.list_hosts() == []


@pytest.mark.asyncio
async def test_list_hosts_exception_returns_empty():
    # Вызов листинга упал → пустой список, публикация идёт обычным путём.
    class _Boom(_FakeHosts):
        async def get_all_hosts(self):
            raise RuntimeError("панель недоступна")

    sdk = _FakeSDK(_FakeNode(), hosts=_Boom())
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    assert await c.list_hosts() == []


@pytest.mark.asyncio
async def test_list_internal_squads():
    c = _client(_FakeNode())
    squads = await c.list_internal_squads()
    assert [s.uuid for s in squads] == ["sq-1", "sq-2"]
    assert squads[0].inbound_uuids == ["inb-x"]
    assert squads[1].inbound_uuids == []


@pytest.mark.asyncio
async def test_add_inbounds_to_squads_merges_without_dups(monkeypatch):
    # Захватываем (uuid, inbounds), которые уйдут в update.
    monkeypatch.setattr(rc, "_build_update_squad_request",
                        lambda uuid, inbounds: (uuid, list(inbounds)))
    sdk = _FakeSDK(_FakeNode())
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    # Дедуп per-squad (ADR 0008): в каждый сквад дописываем оба инбаунда,
    # отбрасывая дубли против ТЕКУЩЕГО состава этого сквада. В sq-1 уже есть
    # inb-x — он не задваивается; sq-2 пустой, поэтому получает оба целиком.
    await c.add_inbounds_to_squads(["sq-1", "sq-2"], ["inb-x", "inb-new"])

    assert sdk.internal_squads.updated == [
        ("sq-1", ["inb-x", "inb-new"]),
        ("sq-2", ["inb-x", "inb-new"]),
    ]


@pytest.mark.asyncio
async def test_add_inbounds_to_squads_unknown_squad():
    c = _client(_FakeNode())
    with pytest.raises(ValueError):
        await c.add_inbounds_to_squads(["sq-missing"], ["inb-1"])


@pytest.mark.asyncio
async def test_add_inbounds_to_squads_noop_on_empty():
    sdk = _FakeSDK(_FakeNode())
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)
    await c.add_inbounds_to_squads([], ["inb-1"])
    await c.add_inbounds_to_squads(["sq-1"], [])
    assert sdk.internal_squads.updated == []


@pytest.mark.asyncio
async def test_get_subscription_settings():
    c = _client(_FakeNode())
    s = await c.get_subscription_settings()
    assert s.uuid == "sub-1"
    assert s.happ_routing is None


@pytest.mark.asyncio
async def test_set_happ_routing_patches_by_uuid(monkeypatch):
    # Захватываем (uuid, value), которые уйдут в PATCH; uuid берётся из GET.
    monkeypatch.setattr(rc, "_build_update_subscription_settings_request",
                        lambda uuid, value: (uuid, value))
    sdk = _FakeSDK(_FakeNode())
    c = RemnawaveClient("https://panel.example", "tok", sdk=sdk)

    await c.set_happ_routing("happ://routing/onadd/XYZ")

    assert sdk.subscriptions_settings.updated_body == ("sub-1", "happ://routing/onadd/XYZ")
