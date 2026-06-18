"""Тесты конвейера provision_node на фейковых зависимостях.

Реального сервера, ansible и панели нет: все швы подставляются через
ProvisionDeps. Проверяем счастливый путь (порядок шагов и финальный online),
ветки сбоя (bootstrap, ansible, поллинг) и выбор inbound'ов.
"""
from __future__ import annotations

import pytest

from orchestrator import ansible_runner, tasks
from orchestrator.remnawave_client import (
    CreatedHost,
    CreatedProfile,
    HostRef,
    InternalSquadRef,
    NodeConnState,
    NodeInfo,
)
from orchestrator.ssh_bootstrap import BootstrapResult
from orchestrator.statemachine import NodeState
from orchestrator.xray_config import GeneratedProfile, HostHint, InboundChoice


class _FakeClient:
    """Фейковая панель: фиксирует вызовы и отдаёт заданный статус ноды."""

    def __init__(self, statuses, existing_hosts=None):
        # statuses — очередь ответов get_node_status (последний повторяется).
        self._statuses = list(statuses)
        self.created_profile_config = None
        self.create_node_kwargs = None
        # Существующие хосты панели для дедупа при повторном провижене; по
        # умолчанию пусто — значит создаём все (поведение чистого провижина).
        self._existing_hosts = list(existing_hosts or [])

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

    async def list_hosts(self):
        # Хосты, уже заведённые в панели (для дедупа при повторном провижене).
        return list(self._existing_hosts)

    async def create_host(self, **kwargs):
        # Накапливаем заведённые хосты для проверок (ADR 0008).
        if not hasattr(self, "hosts_created"):
            self.hosts_created = []
        self.hosts_created.append(kwargs)
        return CreatedHost(
            uuid=f"host-{len(self.hosts_created)}",
            remark=kwargs["remark"], address=kwargs["address"], port=kwargs["port"],
        )

    async def list_internal_squads(self):
        # Две группы доступа; одна уже содержит инбаунд, чтобы проверять дедуп.
        return [
            InternalSquadRef(uuid="sq-1", name="all", inbound_uuids=[]),
            InternalSquadRef(uuid="sq-2", name="vip", inbound_uuids=[]),
        ]

    async def add_inbounds_to_squads(self, squad_uuids, inbound_uuids):
        self.squads_called = (list(squad_uuids), list(inbound_uuids))


def _generated(tags):
    # Раскладка портов как у реального генератора: первый — 443, дальше фолбэки.
    pool = [443, 8443, 2053, 2083, 2087, 2096]
    tags = list(tags)
    ports = {t: pool[i] for i, t in enumerate(tags)}
    # Подсказки хостов: reality для большинства, none для shadowsocks.
    hosts = {
        t: HostHint(
            security="none" if t == "shadowsocks" else "reality",
            network="tcp",
            sni=None if t == "shadowsocks" else "www.microsoft.com",
            fingerprint=None if t == "shadowsocks" else "firefox",
        )
        for t in tags
    }
    return GeneratedProfile(
        config={"inbounds": [{"tag": t} for t in tags]}, tags=tags, ports=ports,
        hosts=hosts,
    )


def _default_vault_get(path):
    """Фейковый Vault для счастливого пути: транзитный bootstrap-секрет (пароль)
    и токен панели. Ключ ноды по nodes/... не сохранён — KeyError, чтобы resume
    по умолчанию не срабатывал."""
    if path.startswith("transient/"):
        return {"auth": "password", "password": "secret"}
    if path.startswith("panels/"):
        return {"token": "tok"}
    raise KeyError(path)


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
        vault_get=_default_vault_get,
    )
    for k, v in over.items():
        setattr(deps, k, v)
    return deps


def _payload(**over):
    p = {
        "node_id": 1,
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "password",
        "panel_url": "https://panel.example",
        "secret_vault_path": "transient/nodes/1/bootstrap",
        "panel_token_vault_path": "panels/7/token",
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
async def test_publish_creates_hosts_and_links_squads():
    # Дефолтный набor — четыре inbound'а; на каждый ожидаем по host'у.
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload())

    # На каждый инбаунд из tag_to_inbound заведён host со своим адресом/портом.
    created = client.hosts_created
    assert [h["inbound_uuid"] for h in created] == ["inb-a", "inb-b", "inb-c", "inb-d"]
    assert created[0]["address"] == "1.2.3.4"          # domain-free → IP ноды
    assert created[0]["port"] == 443
    assert created[0]["security"] == "reality"
    assert created[0]["node_uuid"] == "node-uuid"
    # remark — человекочитаемый: «<флаг> <страна> · <Отпечаток>». Дефолтный
    # payload без country_code → "XX"; reality-инбаунд несёт fingerprint firefox.
    assert created[0]["remark"] == "🇽🇽 XX · Firefox"
    # Сквады не заданы в payload → дефолт «все»: добавили во все сквады панели.
    squads, inbounds = client.squads_called
    assert squads == ["sq-1", "sq-2"]
    assert inbounds == ["inb-a", "inb-b", "inb-c", "inb-d"]


@pytest.mark.asyncio
async def test_publish_skips_existing_hosts_no_dups():
    # Повторный провижн той же ноды: все хосты уже есть в панели → не плодим
    # дубли, create_host не зовётся ни разу. Сверка по (address, port) +
    # inbound_uuid. Дефолтный набор — четыре инбаунда на IP ноды.
    reports = []
    existing = [
        HostRef(uuid="h-a", remark="", address="1.2.3.4", port=443,
                inbound_uuid="inb-a"),
        HostRef(uuid="h-b", remark="", address="1.2.3.4", port=8443,
                inbound_uuid="inb-b"),
        HostRef(uuid="h-c", remark="", address="1.2.3.4", port=2053,
                inbound_uuid="inb-c"),
        HostRef(uuid="h-d", remark="", address="1.2.3.4", port=2083,
                inbound_uuid="inb-d"),
    ]
    client = _FakeClient([NodeConnState.ONLINE], existing_hosts=existing)
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload())

    assert getattr(client, "hosts_created", []) == []
    # Сквады при этом всё равно обновляются — дедуп касается только хостов.
    squads, _ = client.squads_called
    assert squads == ["sq-1", "sq-2"]


@pytest.mark.asyncio
async def test_publish_creates_only_missing_hosts():
    # Часть хостов уже есть (inb-a на 443), часть нет → создаём только
    # недостающие. Хост с тем же адресом, но иным портом не считается дублем.
    reports = []
    existing = [
        HostRef(uuid="h-a", remark="", address="1.2.3.4", port=443,
                inbound_uuid="inb-a"),
    ]
    client = _FakeClient([NodeConnState.ONLINE], existing_hosts=existing)
    deps = _deps(client=client, reports=reports)

    await tasks.provision_node({"deps": deps}, _payload())

    created = client.hosts_created
    # inb-a пропущен, остальные три заведены.
    assert [h["inbound_uuid"] for h in created] == ["inb-b", "inb-c", "inb-d"]


@pytest.mark.asyncio
async def test_publish_uses_selected_squads_from_payload():
    client = _FakeClient([NodeConnState.ONLINE])
    deps = _deps(client=client, reports=[])

    await tasks.provision_node(
        {"deps": deps}, _payload(squad_uuids=["sq-2"])
    )

    squads, _ = client.squads_called
    assert squads == ["sq-2"]


@pytest.mark.asyncio
async def test_publish_tls_host_uses_domain(monkeypatch):
    # Для TLS-инбаунда адрес host'а — домен ноды, а не IP.
    from orchestrator import domain

    client = _TlsClient([NodeConnState.ONLINE])

    async def check_domain(name, ip):
        return domain.DomainCheck(ok=True, detail="")

    deps = _deps(
        client=client, reports=[], check_domain=check_domain,
        build_profile=lambda choices, **kw: GeneratedProfile(
            config={"inbounds": []}, tags=["vless-xhttp-tls"],
            ports={"vless-xhttp-tls": 443},
            hosts={"vless-xhttp-tls": HostHint(
                security="tls", network="xhttp", sni="vpn.example.com", path="/")},
        ),
    )

    await tasks.provision_node(
        {"deps": deps},
        _payload(inbounds=["vless-xhttp-tls"], tls_domain="vpn.example.com"),
    )

    host = client.hosts_created[0]
    assert host["address"] == "vpn.example.com"
    assert host["security"] == "tls"


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
async def test_reality_donor_and_country_reach_pipeline():
    # Донор Reality и код страны из payload (ADR 0007) доходят до генератора и
    # регистрации ноды соответственно.
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    profile_calls = {}

    def build_profile(choices, **kw):
        profile_calls.update(kw)
        return _generated([c.value for c in choices])

    deps = _deps(client=client, reports=reports, build_profile=build_profile)
    await tasks.provision_node(
        {"deps": deps},
        _payload(
            reality_dest="www.cloudflare.com:443",
            reality_server_names=["www.cloudflare.com"],
            country_code="NL",
        ),
    )

    assert profile_calls["reality_dest"] == "www.cloudflare.com:443"
    assert profile_calls["reality_server_names"] == ("www.cloudflare.com",)
    assert client.create_node_kwargs["country_code"] == "NL"


@pytest.mark.asyncio
async def test_reality_donor_defaults_when_absent():
    # Донор не задан → генератор получает дефолт; страна не задана → "XX".
    from orchestrator import xray_config

    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    profile_calls = {}

    def build_profile(choices, **kw):
        profile_calls.update(kw)
        return _generated([c.value for c in choices])

    deps = _deps(client=client, reports=reports, build_profile=build_profile)
    await tasks.provision_node({"deps": deps}, _payload())

    assert profile_calls["reality_dest"] == xray_config.DEFAULT_REALITY_DEST
    assert (
        profile_calls["reality_server_names"]
        == xray_config.DEFAULT_REALITY_SERVER_NAMES
    )
    assert client.create_node_kwargs["country_code"] == "XX"


@pytest.mark.asyncio
async def test_vault_put_uses_node_id_path_not_ip():
    # Ключ ноды адресуется по node_id, а не по IP — две ноды с одним IP не
    # перетирают ключ друг друга.
    reports = []
    stored = {}
    client = _FakeClient([NodeConnState.ONLINE])

    def vault_put(path, data):
        stored[path] = data

    deps = _deps(client=client, reports=reports, vault_put=vault_put)
    await tasks.provision_node({"deps": deps}, _payload())

    # Рядом с ключом кладётся логин SSH (для поздних действий, ADR 0013).
    assert stored == {"nodes/1/ssh": {"private_key": "PRIVKEY", "login": "root"}}


@pytest.mark.asyncio
async def test_transient_secret_deleted_after_bootstrap():
    # Транзитный bootstrap-секрет читается из Vault и стирается после успешного
    # перехода на ключ — в payload его нет, в Vault он не задерживается.
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    deleted = []

    deps = _deps(
        client=client, reports=reports,
        vault_delete=lambda path: deleted.append(path),
    )
    await tasks.provision_node({"deps": deps}, _payload())

    assert deleted == ["transient/nodes/1/bootstrap"]
    assert NodeState.ONLINE in reports


@pytest.mark.asyncio
async def test_panel_token_read_from_vault():
    # Токен панели берётся из Vault по panel_token_vault_path, а не из payload.
    reads = []
    client = _FakeClient([NodeConnState.ONLINE])

    def vault_get(path):
        reads.append(path)
        return _default_vault_get(path)

    deps = _deps(client=client, reports=[], vault_get=vault_get)
    await tasks.provision_node({"deps": deps}, _payload())

    assert "panels/7/token" in reads


@pytest.mark.asyncio
async def test_resume_uses_stored_key_skips_password():
    # Если в Vault уже есть ключ ноды — заходим им, пароль не трогаем.
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    pw_calls = []
    key_calls = []

    async def bootstrap_password(ip, login, password):
        pw_calls.append(ip)
        return BootstrapResult(ok=True, private_key="PRIVKEY")

    async def bootstrap_key(ip, login, private_key):
        key_calls.append(private_key)
        return BootstrapResult(ok=True, private_key=private_key)

    def vault_get(path):
        # Ключ ноды сохранён по node_id; транзит/панель отдаём как обычно.
        if path == "nodes/1/ssh":
            return {"private_key": "STORED"}
        return _default_vault_get(path)

    deps = _deps(
        client=client, reports=reports,
        bootstrap_password=bootstrap_password, bootstrap_key=bootstrap_key,
        vault_get=vault_get,
    )
    await tasks.provision_node({"deps": deps}, _payload())

    assert key_calls == ["STORED"]   # зашли сохранённым ключом
    assert pw_calls == []            # пароль не использовали
    assert NodeState.ONLINE in reports


@pytest.mark.asyncio
async def test_resume_falls_back_when_stored_key_bad():
    # Сохранённый ключ не подошёл — откат на заданный способ (пароль).
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    pw_calls = []

    async def bootstrap_password(ip, login, password):
        pw_calls.append(ip)
        return BootstrapResult(ok=True, private_key="PRIVKEY")

    async def bootstrap_key(ip, login, private_key):
        return BootstrapResult(ok=False, detail="ключ не принят")

    def vault_get(path):
        if path == "nodes/1/ssh":
            return {"private_key": "STORED"}
        return _default_vault_get(path)

    deps = _deps(
        client=client, reports=reports,
        bootstrap_password=bootstrap_password, bootstrap_key=bootstrap_key,
        vault_get=vault_get,
    )
    await tasks.provision_node({"deps": deps}, _payload())

    assert pw_calls == ["1.2.3.4"]   # откатились на пароль
    assert NodeState.ONLINE in reports


@pytest.mark.asyncio
async def test_no_stored_key_uses_payload_auth():
    # Vault пуст для этого IP → обычная развилка по паролю, без resume.
    reports = []
    client = _FakeClient([NodeConnState.ONLINE])
    key_calls = []

    async def bootstrap_key(ip, login, private_key):
        key_calls.append(private_key)
        return BootstrapResult(ok=True, private_key=private_key)

    def vault_get(path):
        # Ключ ноды для этого node_id не сохранён → resume не срабатывает.
        # Транзитный секрет и токен панели доступны как обычно.
        if path.startswith("nodes/"):
            raise KeyError("нет такого пути")
        return _default_vault_get(path)

    deps = _deps(
        client=client, reports=reports,
        bootstrap_key=bootstrap_key, vault_get=vault_get,
    )
    await tasks.provision_node({"deps": deps}, _payload())

    assert key_calls == []           # resume не сработал
    assert NodeState.ONLINE in reports


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


def test_host_remark_format():
    # «<флаг> <страна> · <Отпечаток>»; флаг — regional indicators из ISO-2.
    assert tasks._host_remark("NL", "firefox") == "🇳🇱 Нидерланды · Firefox"
    # Без отпечатка (Shadowsocks) хвост «· …» опускаем.
    assert tasks._host_remark("DE", None) == "🇩🇪 Германия"
    # Неизвестный код: название = сам код, флаг всё равно валиден.
    assert tasks._host_remark("XX", "firefox") == "🇽🇽 XX · Firefox"
    # Нижний регистр нормализуется, пустой код → XX.
    assert tasks._host_remark("nl", None) == "🇳🇱 Нидерланды"
    assert tasks._host_remark("", None) == "🇽🇽 XX"
    # Невалидная длина кода — без флага, не падаем.
    assert tasks._host_remark("BAD", "firefox") == "BAD · Firefox"
    # Лимит панели соблюдается.
    assert len(tasks._host_remark("NL", "firefox")) <= tasks.HOST_REMARK_MAXLEN


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
    key_calls = []

    async def bootstrap_key(ip, login, private_key):
        key_calls.append(private_key)
        return BootstrapResult(ok=True, private_key=private_key)

    def vault_get(path):
        # Транзитный секрет для ветки «ключ» несёт private_key, не пароль.
        if path.startswith("transient/"):
            return {"auth": "key", "private_key": "MYKEY"}
        if path.startswith("nodes/"):
            raise KeyError(path)
        return _default_vault_get(path)

    deps = _deps(
        client=client, reports=reports,
        bootstrap_key=bootstrap_key, vault_get=vault_get,
    )
    await tasks.provision_node({"deps": deps}, _payload(auth="key"))

    assert key_calls == ["MYKEY"]    # ключ взят из транзитного секрета Vault
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


# ==========================================================================
# Разворот панели с нуля (provision_panel, ADR 0001) — на фейках.
# ==========================================================================
class _FakeVault:
    """Фейковый Vault для разворота панели: хранит секреты в памяти.

    Транзитный пароль админа кладётся ботом; провижн читает его, выдаёт токен и
    стирает транзит. Боевой токен и Panel пишет persist_panel (шов deps)."""

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.deleted: list[str] = []

    def get(self, path):
        if path not in self.store:
            raise KeyError(path)
        return self.store[path]

    def put(self, path, data):
        self.store[path] = dict(data)

    def delete(self, path):
        self.deleted.append(path)
        self.store.pop(path, None)


class _FakeLocalCompose:
    """Фейковый локальный compose: фиксирует записанные файлы и факт запуска."""

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.written = None
        self.upped = False

    def write_stack(self, compose, caddyfile, env):
        self.written = {"compose": compose, "caddyfile": caddyfile, "env": env}
        return self.base_dir

    def up(self, cwd):
        self.upped = True


def _panel_deps(*, vault, reports, run_playbook=None, provision_admin=None,
                make_local_compose=None, persist_panel=None):
    """Собрать ProvisionDeps для разворота панели со счастливыми дефолтами."""
    async def report(state, detail):
        reports.append((state, detail))

    async def bootstrap_password(ip, login, password):
        return BootstrapResult(ok=True, private_key="PRIVKEY")

    async def bootstrap_key(ip, login, private_key):
        return BootstrapResult(ok=True, private_key=private_key)

    async def default_run_playbook(playbook, host, login, private_key, **kw):
        return ansible_runner.PlaybookResult(ok=True)

    async def default_provision_admin(panel_url, username, password, **kw):
        return "PANEL-API-TOKEN"

    async def sleep(_):
        return None

    return tasks.ProvisionDeps(
        bootstrap_password=bootstrap_password,
        bootstrap_key=bootstrap_key,
        run_playbook=run_playbook or default_run_playbook,
        provision_panel_admin=provision_admin or default_provision_admin,
        make_local_compose=make_local_compose or _FakeLocalCompose,
        report=report,
        sleep=sleep,
        vault_get=vault.get,
        vault_put=vault.put,
        vault_delete=vault.delete,
        persist_panel=persist_panel,
    )


def _panel_payload(**over):
    p = {
        "owner": 7,
        "chat_id": 100,
        "placement": "vps",
        "panel_domain": "panel.example",
        "admin_username": "admin",
        "admin_secret_vault_path": "transient/panels/7/admin",
        "ip": "1.2.3.4",
        "login": "root",
        "auth": "password",
        "secret_vault_path": "transient/panels/7/bootstrap",
    }
    p.update(over)
    return p


@pytest.mark.asyncio
async def test_provision_panel_vps_happy_path():
    vault = _FakeVault()
    vault.put("transient/panels/7/admin", {"password": "S3cret" + "x" * 20})
    vault.put("transient/panels/7/bootstrap", {"auth": "password", "password": "pw"})
    reports = []
    saved = {}
    played = []

    async def run_playbook(playbook, host, login, private_key, **kw):
        played.append(str(playbook))
        return ansible_runner.PlaybookResult(ok=True)

    admin_seen = {}

    async def provision_admin(panel_url, username, password, **kw):
        admin_seen.update(url=panel_url, username=username, password=password)
        return "PANEL-API-TOKEN"

    async def persist_panel(*, url, token):
        saved.update(url=url, token=token)

    deps = _panel_deps(
        vault=vault, reports=reports, run_playbook=run_playbook,
        provision_admin=provision_admin, persist_panel=persist_panel,
    )

    await tasks.provision_panel({"deps": deps}, _panel_payload())

    # Регистрация шла на https://<домен> (Caddy выпускает TLS).
    assert admin_seen["url"] == "https://panel.example"
    assert admin_seen["username"] == "admin"
    # Пароль админа прочитан из Vault, а не из payload.
    assert admin_seen["password"].startswith("S3cret")
    # Прогоняли hardening и deploy_panel.
    assert any("hardening" in p for p in played)
    assert any("deploy_panel" in p for p in played)
    # Токен и URL сохранены через persist_panel.
    assert saved == {"url": "https://panel.example", "token": "PANEL-API-TOKEN"}
    # Транзитные секреты (пароль админа и доступ-секрет) стёрты.
    assert "transient/panels/7/admin" in vault.deleted
    assert "transient/panels/7/bootstrap" in vault.deleted
    # До FAILED не дошли.
    assert NodeState.FAILED not in [s for s, _ in reports]


@pytest.mark.asyncio
async def test_provision_panel_local_happy_path():
    vault = _FakeVault()
    vault.put("transient/panels/7/admin", {"password": "S3cret" + "x" * 20})
    reports = []
    saved = {}
    made = {}

    def make_local_compose(base_dir):
        stack = _FakeLocalCompose(base_dir)
        made["stack"] = stack
        return stack

    async def persist_panel(*, url, token):
        saved.update(url=url, token=token)

    deps = _panel_deps(
        vault=vault, reports=reports,
        make_local_compose=make_local_compose, persist_panel=persist_panel,
    )

    # local: ни ip/login/auth, ни secret_vault_path в payload.
    payload = {
        "owner": 7,
        "chat_id": 100,
        "placement": "local",
        "panel_domain": "panel.example",
        "admin_username": "admin",
        "admin_secret_vault_path": "transient/panels/7/admin",
    }
    await tasks.provision_panel({"deps": deps}, payload)

    # Локальный стек собран и поднят, файлы записаны.
    stack = made["stack"]
    assert stack.upped is True
    assert "remnawave" in stack.written["compose"]
    assert "panel.example" in stack.written["caddyfile"]
    assert "FRONT_END_DOMAIN=panel.example" in stack.written["env"]
    # Токен сохранён, пароль админа стёрт; bootstrap-секрета не было.
    assert saved == {"url": "https://panel.example", "token": "PANEL-API-TOKEN"}
    assert "transient/panels/7/admin" in vault.deleted
    assert NodeState.FAILED not in [s for s, _ in reports]


@pytest.mark.asyncio
async def test_provision_panel_admin_failure_goes_failed():
    vault = _FakeVault()
    vault.put("transient/panels/7/admin", {"password": "S3cret" + "x" * 20})
    reports = []

    async def provision_admin(panel_url, username, password, **kw):
        from orchestrator.panel_setup import PanelSetupError
        raise PanelSetupError("панель не поднялась")

    deps = _panel_deps(
        vault=vault, reports=reports, provision_admin=provision_admin,
    )
    payload = {
        "owner": 7, "chat_id": 100, "placement": "local",
        "panel_domain": "panel.example", "admin_username": "admin",
        "admin_secret_vault_path": "transient/panels/7/admin",
    }
    await tasks.provision_panel({"deps": deps}, payload)

    assert NodeState.FAILED in [s for s, _ in reports]
