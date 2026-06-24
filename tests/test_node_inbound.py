"""Тесты добавления инбаунда к развёрнутой ноде (orchestrator/node_inbound.py).

Фейковый клиент панели и фейковый open_port: проверяем read-modify-write
(новый inbound дописан в config, не затёр старые), выбор свободного порта,
переиспользование домена/сертификата из существующего TLS-инбаунда для Hysteria2,
включение нового инбаунда в активные у ноды и отказ доменному инбаунду без домена.
"""
from __future__ import annotations

import pytest

from orchestrator import node_inbound
from orchestrator.node_inbound import add_inbound_to_node
from orchestrator.remnawave_client import (
    CreatedProfile,
    FetchedProfile,
    InternalSquadRef,
    NodeProfileRef,
)
from orchestrator.xray_config import InboundChoice


class FakeOpenPort:
    def __init__(self, ok=True, detail="ok"):
        self.ok, self.detail = ok, detail
        self.calls = []

    async def __call__(self, ip, login, key, port, *, udp=False):
        self.calls.append((ip, port, udp))
        return self


class FakeClient:
    """Минимальный фейк панели для add_inbound_to_node."""

    def __init__(self, *, config, active=("inb-old",), profile_uuid="prof-1"):
        self._config = config
        self._active = list(active)
        self._profile_uuid = profile_uuid
        self.created_hosts = []
        self.squad_updates = []
        self.node_update = None
        self.updated_config = None

    async def get_node_config(self, uuid):
        return NodeProfileRef(
            node_uuid=uuid, profile_uuid=self._profile_uuid,
            active_inbound_uuids=list(self._active),
        )

    async def get_config_profile(self, uuid):
        return FetchedProfile(
            uuid=uuid, name="default", config=self._config,
            tag_to_inbound={},
        )

    async def update_config_profile(self, uuid, config):
        self.updated_config = config
        # Панель пересобирает inbounds: тег→uuid для каждого инбаунда в config.
        mapping = {
            inb["tag"]: f"uuid-{inb['tag']}"
            for inb in config["inbounds"] if inb.get("tag")
        }
        return CreatedProfile(uuid=uuid, tag_to_inbound=mapping)

    async def update_node_active_inbounds(self, uuid, profile_uuid, inbounds):
        self.node_update = (uuid, profile_uuid, list(inbounds))

    async def create_host(self, **kwargs):
        self.created_hosts.append(kwargs)

    async def list_internal_squads(self):
        return [InternalSquadRef(uuid="sq-1", name="all", inbound_uuids=[])]

    async def add_inbounds_to_squads(self, squads, inbounds):
        self.squad_updates.append((list(squads), list(inbounds)))


def _reality_config():
    """Профиль с одним domain-free reality-инбаундом на 443."""
    return {
        "inbounds": [
            {"tag": "vless-reality-tcp-1-2-3-4", "port": 443,
             "streamSettings": {"security": "reality"}},
        ]
    }


def _tls_config():
    """Профиль с TLS-инбаундом (есть домен и пути сертификата)."""
    return {
        "inbounds": [
            {"tag": "vless-xhttp-tls-1-2-3-4", "port": 443,
             "streamSettings": {
                 "security": "tls",
                 "tlsSettings": {
                     "serverName": "vpn.example.com",
                     "certificates": [
                         {"certificateFile": "/c/fullchain.pem",
                          "keyFile": "/c/key.pem"},
                     ],
                 },
             }},
        ]
    }


async def _run(choice, config, **kw):
    client = FakeClient(config=config)
    op = FakeOpenPort(**kw.pop("op", {}))
    res = await add_inbound_to_node(
        choice=choice, ip="1.2.3.4", node_uuid="node-1", country_code="NL",
        ssh_login="root", ssh_private_key="PRIV", client=client, open_port=op, **kw,
    )
    return res, client, op


@pytest.mark.asyncio
async def test_add_domain_free_inbound_picks_free_port():
    res, client, op = await _run(InboundChoice.VLESS_GRPC_REALITY, _reality_config())
    assert res.ok, res.detail
    # 443 занят — новый сел на первый фолбэк (8443), порт открыт по tcp.
    assert op.calls == [("1.2.3.4", 8443, False)]
    # Старый инбаунд не затёрт, новый дописан.
    tags = {i["tag"] for i in client.updated_config["inbounds"]}
    assert "vless-reality-tcp-1-2-3-4" in tags
    assert "vless-grpc-reality-1-2-3-4" in tags
    # Новый инбаунд включён в активные у ноды (к старому добавлен).
    _, _, active = client.node_update
    assert "inb-old" in active
    assert "uuid-vless-grpc-reality-1-2-3-4" in active
    # Host и сквад заведены.
    assert len(client.created_hosts) == 1
    assert client.squad_updates


@pytest.mark.asyncio
async def test_add_hysteria2_reuses_domain_and_opens_udp():
    res, client, op = await _run(InboundChoice.HYSTERIA2, _tls_config())
    assert res.ok, res.detail
    # Hysteria2 — UDP; порт открыт по udp.
    assert op.calls == [("1.2.3.4", 8443, True)]
    # Новый инбаунд использует домен/cert из существующего TLS-инбаунда.
    hy2 = next(
        i for i in client.updated_config["inbounds"]
        if i["tag"] == "hysteria2-1-2-3-4"
    )
    tls = hy2["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "vpn.example.com"
    assert tls["certificates"][0]["certificateFile"] == "/c/fullchain.pem"
    # Host заведён на домен (а не IP) для TLS.
    assert client.created_hosts[0]["address"] == "vpn.example.com"


@pytest.mark.asyncio
async def test_domain_inbound_rejected_without_domain():
    res, client, op = await _run(InboundChoice.HYSTERIA2, _reality_config())
    assert res.ok is False
    assert "домен" in res.detail.lower()
    # Ничего не меняли — профиль не обновлялся.
    assert client.updated_config is None
    assert op.calls == []


@pytest.mark.asyncio
async def test_open_port_failure_reported():
    res, client, op = await _run(
        InboundChoice.SHADOWSOCKS, _reality_config(),
        op={"ok": False, "detail": "сервер недоступен"},
    )
    assert res.ok is False
    assert "порт" in res.detail.lower()
