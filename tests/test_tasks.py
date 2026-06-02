"""Тесты конвейера provision_node на фейковых зависимостях.

Реального сервера, ansible и панели нет: все швы подставляются через
ProvisionDeps. Проверяем счастливый путь (порядок шагов и финальный online),
ветки сбоя (bootstrap, ansible, поллинг) и выбор inbound'ов.
"""
from __future__ import annotations

import pytest

from orchestrator import ansible_runner, tasks
from orchestrator.remnawave_client import (
    CreatedProfile,
    NodeConnState,
    NodeInfo,
)
from orchestrator.ssh_bootstrap import BootstrapResult
from orchestrator.statemachine import NodeState
from orchestrator.xray_config import GeneratedProfile, InboundChoice


class _FakeClient:
    """Фейковая панель: фиксирует вызовы и отдаёт заданный статус ноды."""

    def __init__(self, statuses):
        # statuses — очередь ответов get_node_status (последний повторяется).
        self._statuses = list(statuses)
        self.created_profile_config = None
        self.create_node_kwargs = None

    async def get_panel_pubkey(self):
        return "PANEL_PUBKEY"

    async def create_config_profile(self, name, config):
        self.created_profile_config = config
        # Панель присваивает inbound'ам uuid'ы и возвращает их по тегам.
        return CreatedProfile(
            uuid="prof-1",
            tag_to_inbound={
                "vless-reality-tcp": "inb-a",
                "vless-xhttp-reality": "inb-b",
                "vless-grpc-reality": "inb-c",
                "shadowsocks": "inb-d",
            },
        )

    async def create_node(self, **kwargs):
        self.create_node_kwargs = kwargs
        return NodeInfo(
            uuid="node-uuid", name=kwargs["name"], address=kwargs["address"],
            port=kwargs["port"], status=NodeConnState.CONNECTING,
        )

    async def get_node_status(self, uuid):
        if len(self._statuses) > 1:
            return self._statuses.pop(0)
        return self._statuses[0]


def _generated(tags):
    return GeneratedProfile(
        config={"inbounds": [{"tag": t} for t in tags]}, tags=list(tags)
    )


def _deps(*, client, **over):
    """Собрать ProvisionDeps со счастливыми дефолтами и инъекцией клиента."""
    reports = over.pop("reports")

    async def report(state, detail):
        reports.append(state)

    async def bootstrap_password(ip, login, password):
        return BootstrapResult(ok=True, private_key="PRIVKEY")

    async def bootstrap_key(ip, login, private_key):
        return BootstrapResult(ok=True, private_key=private_key)

    async def run_playbook(playbook, host, login, private_key, **kw):
        return ansible_runner.PlaybookResult(ok=True)

    def build_profile(choices, **kw):
        return _generated([c.value for c in choices])

    async def sleep(_):
        return None

    deps = tasks.ProvisionDeps(
        bootstrap_password=bootstrap_password,
        bootstrap_key=bootstrap_key,
        run_playbook=run_playbook,
        build_profile=build_profile,
        make_client=lambda url, tok: client,
        report=report,
        sleep=sleep,
        poll_attempts=3,
        poll_interval_sec=0,
    )
    for k, v in over.items():
        setattr(deps, k, v)
    return deps


def _payload(**over):
    p = {
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "password",
        "password": "secret",
        "panel_url": "https://panel.example",
        "panel_token": "tok",
    }
    p.update(over)
    return p


@pytest.mark.asyncio
async def test_happy_path_reaches_online():
    reports = []
    client = _FakeClient([NodeConnState.CONNECTING, NodeConnState.ONLINE])
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload())

    assert NodeState.ONLINE in reports
    assert NodeState.FAILED not in reports
    # Порядок ключевых состояний. Во время поллинга прогресс-отчёт легитимно
    # повторяет текущее состояние (REGISTERING), поэтому схлопываем подряд
    # идущие дубли — нас интересует именно порядок переходов.
    transitions = {
        NodeState.BOOTSTRAPPING, NodeState.PROVISIONING,
        NodeState.REGISTERING, NodeState.ONLINE,
    }
    key: list[NodeState] = []
    for s in reports:
        if s in transitions and (not key or key[-1] is not s):
            key.append(s)
    assert key == [
        NodeState.BOOTSTRAPPING, NodeState.PROVISIONING,
        NodeState.REGISTERING, NodeState.ONLINE,
    ]
    # create_node получил наш порт и профиль.
    assert client.create_node_kwargs["port"] == tasks.NODE_APP_PORT
    assert client.create_node_kwargs["config_profile_uuid"] == "prof-1"


@pytest.mark.asyncio
async def test_default_inbounds_are_domain_free():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload())

    # По дефолту — четыре domain-free inbound'а, все попали в active_inbounds.
    active = client.create_node_kwargs["active_inbounds"]
    assert set(active) == {"inb-a", "inb-b", "inb-c", "inb-d"}


@pytest.mark.asyncio
async def test_vault_put_called_with_key_not_password():
    reports = []
    stored = {}
    client = _FakeClient([NodeConnState.ONLINE])

    def vault_put(path, data):
        stored[path] = data

    deps = _deps(client=client, reports=reports, vault_put=vault_put)
    await tasks.provision_node({"deps": deps}, _payload())

    assert stored == {"nodes/1.2.3.4/ssh": {"private_key": "PRIVKEY"}}


@pytest.mark.asyncio
async def test_bootstrap_failure_goes_failed():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])

    async def bad_bootstrap(ip, login, password):
        return BootstrapResult(ok=False, detail="не Ubuntu")

    deps = _deps(client=client, reports=reports, bootstrap_password=bad_bootstrap)
    await tasks.provision_node({"deps": deps}, _payload())

    assert reports[-1] is NodeState.FAILED
    assert NodeState.PROVISIONING not in reports


@pytest.mark.asyncio
async def test_ansible_failure_goes_failed():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])

    async def bad_playbook(playbook, host, login, private_key, **kw):
        return ansible_runner.PlaybookResult(ok=False, detail="ufw упал")

    deps = _deps(client=client, reports=reports, run_playbook=bad_playbook)
    await tasks.provision_node({"deps": deps}, _payload())

    assert reports[-1] is NodeState.FAILED
    assert NodeState.REGISTERING not in reports


@pytest.mark.asyncio
async def test_poll_timeout_goes_failed():
    reports = []
    # Нода никогда не выходит online → исчерпание попыток.
    client = _FakeClient([NodeConnState.CONNECTING])
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload())

    assert reports[-1] is NodeState.FAILED
    assert NodeState.ONLINE not in reports


@pytest.mark.asyncio
async def test_new_panel_mode_rejected():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload(panel_mode="new"))

    assert reports[-1] is NodeState.FAILED


@pytest.mark.asyncio
async def test_key_branch_uses_private_key():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    deps = _deps(client=client, reports=reports)

    payload = _payload(auth="key", private_key="MYKEY")
    payload.pop("password")
    await tasks.provision_node({"deps": deps}, payload)

    assert NodeState.ONLINE in reports


@pytest.mark.asyncio
async def test_unknown_inbound_in_payload_fails():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload(inbounds=["bogus"]))

    assert reports[-1] is NodeState.FAILED
