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
    # Раскладка портов как у реального генератора: первый — 443, дальше фолбэки.
    pool = [443, 8443, 2053, 2083, 2087, 2096]
    tags = list(tags)
    ports = {t: pool[i] for i, t in enumerate(tags)}
    return GeneratedProfile(
        config={"inbounds": [{"tag": t} for t in tags]}, tags=tags, ports=ports
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


# --- TLS-ветка (ADR 0005): домен-гейт + выпуск сертификата ----------------

class _TlsClient(_FakeClient):
    """Панель, знающая про TLS-инбаунд: возвращает его uuid по тегу."""

    async def create_config_profile(self, name, config):
        self.created_profile_config = config
        return CreatedProfile(
            uuid="prof-tls",
            tag_to_inbound={"vless-xhttp-tls": "inb-tls"},
        )


def _tls_deps(*, client, reports, **over):
    """ProvisionDeps для TLS: build_profile и run_playbook фиксируют вызовы,
    check_domain по умолчанию подтверждает совпадение домена."""
    from orchestrator import domain

    profile_calls = {}
    playbooks = []
    over_check = over.pop("check_domain", None)

    def build_profile(choices, **kw):
        profile_calls.update(kw)
        return _generated([c.value for c in choices])

    async def run_playbook(playbook, host, login, private_key, **kw):
        from pathlib import Path
        playbooks.append(Path(str(playbook)).name)
        return ansible_runner.PlaybookResult(ok=True)

    async def check_domain(domain_name, expected_ip):
        return domain.DomainCheck(ok=True, detail="ok", resolved=[expected_ip])

    deps = _deps(
        client=client, reports=reports,
        build_profile=build_profile, run_playbook=run_playbook,
        check_domain=over_check or check_domain, **over,
    )
    return deps, profile_calls, playbooks


@pytest.mark.asyncio
async def test_tls_issues_cert_and_passes_paths():
    reports = []
    client = _TlsClient([NodeConnState.ONLINE])
    deps, profile_calls, playbooks = _tls_deps(client=client, reports=reports)

    await tasks.provision_node(
        {"deps": deps},
        _payload(inbounds=["vless-xhttp-tls"], tls_domain="vpn.example.com"),
    )

    assert NodeState.ONLINE in reports
    # issue_cert прогнан до deploy_node
    assert "issue_cert.yml" in playbooks
    assert playbooks.index("issue_cert.yml") < playbooks.index("deploy_node.yml")
    # пути сертификата проброшены в build_profile внутри контейнера
    assert profile_calls["tls_domain"] == "vpn.example.com"
    assert profile_calls["cert_file"].endswith("/vpn.example.com/fullchain.pem")
    assert profile_calls["cert_file"].startswith(tasks.NODE_CERT_DIR_CONTAINER)


@pytest.mark.asyncio
async def test_tls_without_domain_fails():
    reports = []
    client = _TlsClient([NodeConnState.ONLINE])
    deps, _, playbooks = _tls_deps(client=client, reports=reports)

    await tasks.provision_node(
        {"deps": deps}, _payload(inbounds=["vless-xhttp-tls"])  # домена нет
    )

    assert reports[-1] is NodeState.FAILED
    assert "issue_cert.yml" not in playbooks


@pytest.mark.asyncio
async def test_tls_domain_mismatch_blocks_issue():
    from orchestrator import domain

    reports = []
    client = _TlsClient([NodeConnState.ONLINE])

    async def bad_check(domain_name, expected_ip):
        return domain.DomainCheck(ok=False, detail="смотрит не туда")

    deps, _, playbooks = _tls_deps(
        client=client, reports=reports, check_domain=bad_check
    )

    await tasks.provision_node(
        {"deps": deps},
        _payload(inbounds=["vless-xhttp-tls"], tls_domain="vpn.example.com"),
    )

    assert reports[-1] is NodeState.FAILED
    # гейт не прошёл → сертификат не выпускаем
    assert "issue_cert.yml" not in playbooks


# --- Открытие портов inbound'ов в UFW ---------------------------------------

def _recording_run_playbook(calls):
    """run_playbook, фиксирующий имя плейбука и extra_vars каждого вызова."""
    from pathlib import Path

    async def run_playbook(playbook, host, login, private_key, **kw):
        calls.append((Path(str(playbook)).name, kw.get("extra_vars") or {}))
        return ansible_runner.PlaybookResult(ok=True)

    return run_playbook


@pytest.mark.asyncio
async def test_open_ports_uses_only_occupied_ports():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    calls = []
    deps = _deps(client=client, reports=reports,
                 run_playbook=_recording_run_playbook(calls))

    await tasks.provision_node({"deps": deps}, _payload())

    names = [n for n, _ in calls]
    open_calls = [ev for n, ev in calls if n == "open_ports.yml"]
    assert len(open_calls) == 1
    ports = open_calls[0]["inbound_ports"]
    # Ровно порты четырёх domain-free дефолтов, отсортированы, без дублей.
    assert ports == [443, 2053, 2083, 8443]
    # Лишних портов из пула фолбэков не уходит (5-й фолбэк 2087/2096 не занят).
    assert 2087 not in ports and 2096 not in ports
    # Порты открываем до старта контейнера ноды.
    assert names.index("open_ports.yml") < names.index("deploy_node.yml")


@pytest.mark.asyncio
async def test_domain_free_set_does_not_open_port_80():
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    calls = []
    deps = _deps(client=client, reports=reports,
                 run_playbook=_recording_run_playbook(calls))

    await tasks.provision_node({"deps": deps}, _payload())

    names = [n for n, _ in calls]
    # 80 нужен только для ACME (issue_cert), которого в domain-free наборе нет.
    assert "issue_cert.yml" not in names
    open_ports = [ev["inbound_ports"] for n, ev in calls if n == "open_ports.yml"][0]
    assert 80 not in open_ports


@pytest.mark.asyncio
async def test_tls_open_ports_excludes_80():
    reports = []
    client = _TlsClient([NodeConnState.ONLINE])
    calls = []
    # check_domain должен подтвердить совпадение, иначе сертификат не выпустим.
    from orchestrator import domain

    async def check_domain(domain_name, expected_ip):
        return domain.DomainCheck(ok=True, detail="ok", resolved=[expected_ip])

    deps = _deps(client=client, reports=reports,
                 run_playbook=_recording_run_playbook(calls),
                 check_domain=check_domain)

    await tasks.provision_node(
        {"deps": deps},
        _payload(inbounds=["vless-xhttp-tls"], tls_domain="vpn.example.com"),
    )

    names = [n for n, _ in calls]
    open_ports = [ev["inbound_ports"] for n, ev in calls if n == "open_ports.yml"][0]
    # 80 открывает issue_cert.yml, в open_ports его не дублируем.
    assert "issue_cert.yml" in names
    assert open_ports == [443]
    assert 80 not in open_ports
