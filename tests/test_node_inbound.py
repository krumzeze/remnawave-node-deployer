"""Тесты добавления инбаунда к развёрнутой ноде (orchestrator/node_inbound.py).

Фейковый клиент панели и фейковый open_port: проверяем read-modify-write
(новый inbound дописан в config, не затёр старые), выбор свободного порта,
переиспользование домена/сертификата из существующего TLS-инбаунда для Hysteria2,
включение нового инбаунда в активные у ноды и отказ доменному инбаунду без домена.
"""
from __future__ import annotations

import pytest

from orchestrator import node_inbound
from orchestrator.node_inbound import add_inbound_to_node, remove_inbound_from_node
from orchestrator.remnawave_client import (
    CreatedProfile,
    FetchedProfile,
    HostRef,
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

    def __init__(self, *, config, active=("inb-old",), profile_uuid="prof-1",
                 tag_to_inbound=None, hosts=()):
        self._config = config
        self._active = list(active)
        self._profile_uuid = profile_uuid
        self._tag_to_inbound = dict(tag_to_inbound or {})
        self._hosts = list(hosts)
        self.created_hosts = []
        self.deleted_hosts = []
        self.squad_updates = []
        self.squads_removed = []
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
            tag_to_inbound=dict(self._tag_to_inbound),
        )

    async def list_hosts(self):
        return list(self._hosts)

    async def delete_host(self, uuid):
        self.deleted_hosts.append(uuid)

    async def remove_inbounds_from_squads(self, inbound_uuids):
        self.squads_removed.append(list(inbound_uuids))

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
async def test_add_inbound_skips_ports_busy_on_server():
    # 443 занят профилем, 8443 — чужим процессом на сервере (nginx): новый
    # инбаунд обходит оба и садится на следующий фолбэк.
    async def probe(ip, login, key, **kw):
        return {8443}

    res, client, op = await _run(
        InboundChoice.VLESS_GRPC_REALITY, _reality_config(), probe_ports=probe,
    )
    assert res.ok, res.detail
    assert op.calls == [("1.2.3.4", 8444, False)]


@pytest.mark.asyncio
async def test_add_inbound_probe_failure_ignored():
    # Проба портов не удалась (None) — выбор порта идёт только по профилю.
    async def probe(ip, login, key, **kw):
        return None

    res, client, op = await _run(
        InboundChoice.VLESS_GRPC_REALITY, _reality_config(), probe_ports=probe,
    )
    assert res.ok, res.detail
    assert op.calls == [("1.2.3.4", 8443, False)]


@pytest.mark.asyncio
async def test_add_reality_inbound_reuses_node_donor():
    # Нода разворачивалась с кастомным донором Reality — добавляемый Reality-
    # инбаунд должен взять его же (dest/serverNames и sni хоста), а не дефолт.
    config = {
        "inbounds": [
            {"tag": "vless-reality-tcp-1-2-3-4", "port": 443,
             "streamSettings": {
                 "security": "reality",
                 "realitySettings": {
                     "dest": "www.cloudflare.com:443",
                     "serverNames": ["www.cloudflare.com"],
                 },
             }},
        ]
    }
    res, client, op = await _run(InboundChoice.VLESS_GRPC_REALITY, config)
    assert res.ok, res.detail
    new_inb = next(
        i for i in client.updated_config["inbounds"]
        if i["tag"] == "vless-grpc-reality-1-2-3-4"
    )
    rs = new_inb["streamSettings"]["realitySettings"]
    assert rs["dest"] == "www.cloudflare.com:443"
    assert rs["serverNames"] == ["www.cloudflare.com"]
    assert client.created_hosts[0]["sni"] == "www.cloudflare.com"


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


# --------------------------------------------------------------------------
# Удаление инбаунда с ноды (remove_inbound_from_node).
# --------------------------------------------------------------------------
def _two_inbound_config():
    return {
        "inbounds": [
            {"tag": "vless-reality-tcp-1-2-3-4", "port": 443,
             "streamSettings": {"security": "reality"}},
            {"tag": "vless-grpc-reality-1-2-3-4", "port": 8443,
             "streamSettings": {"security": "reality"}},
        ]
    }


_TWO_TAGS = {
    "vless-reality-tcp-1-2-3-4": "inb-r",
    "vless-grpc-reality-1-2-3-4": "inb-g",
}


async def _run_remove(choice, client, *, key="PRIV", close=None):
    close = close or FakeOpenPort()
    res = await remove_inbound_from_node(
        choice=choice, ip="1.2.3.4", node_uuid="node-1",
        ssh_login="root", ssh_private_key=key,
        client=client, close_port=close,
    )
    return res, close


@pytest.mark.asyncio
async def test_remove_inbound_cleans_everything():
    hosts = [
        HostRef(uuid="h-r", remark="", address="1.2.3.4", port=443,
                inbound_uuid="inb-r"),
        HostRef(uuid="h-g", remark="", address="1.2.3.4", port=8443,
                inbound_uuid="inb-g"),
    ]
    client = FakeClient(
        config=_two_inbound_config(), active=("inb-r", "inb-g"),
        tag_to_inbound=_TWO_TAGS, hosts=hosts,
    )
    res, close = await _run_remove(InboundChoice.VLESS_GRPC_REALITY, client)
    assert res.ok, res.detail
    # Хост удалён только у удаляемого инбаунда; сквады вычищены.
    assert client.deleted_hosts == ["h-g"]
    assert client.squads_removed == [["inb-g"]]
    # Профиль обновлён без инбаунда, второй не тронут.
    tags = {i["tag"] for i in client.updated_config["inbounds"]}
    assert tags == {"vless-reality-tcp-1-2-3-4"}
    # Активные у ноды — свежий uuid оставшегося (карта после update).
    _, _, active = client.node_update
    assert active == ["uuid-vless-reality-tcp-1-2-3-4"]
    # Порт инбаунда закрыт (tcp: не SS/Hysteria2).
    assert close.calls == [("1.2.3.4", 8443, False)]


@pytest.mark.asyncio
async def test_remove_last_inbound_refused():
    client = FakeClient(
        config=_reality_config(), active=("inb-r",),
        tag_to_inbound={"vless-reality-tcp-1-2-3-4": "inb-r"},
    )
    res, close = await _run_remove(InboundChoice.VLESS_REALITY_TCP, client)
    assert res.ok is False
    assert "последний" in res.detail.lower()
    # Ничего не тронуто.
    assert client.updated_config is None
    assert client.deleted_hosts == []
    assert close.calls == []


@pytest.mark.asyncio
async def test_remove_missing_inbound_refused():
    client = FakeClient(
        config=_two_inbound_config(), tag_to_inbound=_TWO_TAGS,
    )
    res, _ = await _run_remove(InboundChoice.HYSTERIA2, client)
    assert res.ok is False
    assert client.updated_config is None


@pytest.mark.asyncio
async def test_remove_without_ssh_cleans_panel_but_warns_about_port():
    client = FakeClient(
        config=_two_inbound_config(), active=("inb-r", "inb-g"),
        tag_to_inbound=_TWO_TAGS,
    )
    res, close = await _run_remove(
        InboundChoice.VLESS_GRPC_REALITY, client, key=None,
    )
    assert res.ok, res.detail
    # Панель вычищена, но порт остался открыт — об этом сказано прямо.
    assert client.updated_config is not None
    assert close.calls == []
    assert "порт" in res.detail.lower() and "откры" in res.detail.lower()


@pytest.mark.asyncio
async def test_remove_matches_host_without_inbound_uuid_by_port_and_address():
    # У хоста нет uuid инбаунда (форма SDK) — матчим по порту и адресу ноды;
    # чужой хост на том же порту, но с другим адресом не задет.
    hosts = [
        HostRef(uuid="h-ours", remark="", address="1.2.3.4", port=8443,
                inbound_uuid=None),
        HostRef(uuid="h-foreign", remark="", address="9.9.9.9", port=8443,
                inbound_uuid=None),
    ]
    client = FakeClient(
        config=_two_inbound_config(), active=("inb-r", "inb-g"),
        tag_to_inbound=_TWO_TAGS, hosts=hosts,
    )
    res, _ = await _run_remove(InboundChoice.VLESS_GRPC_REALITY, client)
    assert res.ok, res.detail
    assert client.deleted_hosts == ["h-ours"]
