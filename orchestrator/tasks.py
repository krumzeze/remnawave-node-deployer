"""Задачи очереди arq и воркер.

Воркер берёт provision_node из Redis и прогоняет state-машину:
bootstrap → ansible (hardening + deploy remnanode) → генерация Xray-конфига →
create_config_profile → create_node → поллинг до online. Статусы шлются обратно
в Telegram/веб через callback `report`.

provision_node собран из инъектируемых зависимостей (`ProvisionDeps`): по
умолчанию это реальные модули (ssh_bootstrap, ansible_runner, RemnawaveClient,
Vault), а в тестах подставляются фейки. Так конвейер проверяется без реального
сервера, ansible и панели — тем же приёмом, что и в остальных модулях проекта.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from arq.connections import RedisSettings

from config import settings
from orchestrator import ansible_runner, domain, reporting, ssh_bootstrap, xray_config
from orchestrator.remnawave_client import NodeConnState, RemnawaveClient
from orchestrator.statemachine import NodeState, can_transition
from orchestrator.xray_config import TLS_CHOICES, InboundChoice

logger = logging.getLogger(__name__)

# Порт, на котором слушает контейнер remnanode (APP_PORT) и который мы же
# регистрируем в панели через create_node. Значение одно: панель должна
# стучаться ровно туда, куда нода слушает. 2222 — дефолт образа remnawave/node.
NODE_APP_PORT = 2222

# Дефолтный набор inbound'ов (ADR 0005 «дефолт все»), но только domain-free:
# TLS-ветки требуют домена и сертификата acme.sh. В дефолт они не входят — домен
# спрашиваем только при явном выборе TLS (см. selection_needs_domain в боте).
# Если payload явно пришлёт TLS-вариант без домена, _setup_tls упадёт с понятной
# ошибкой и конвейер уйдёт в failed.
DEFAULT_INBOUNDS: tuple[InboundChoice, ...] = (
    InboundChoice.VLESS_REALITY_TCP,
    InboundChoice.VLESS_XHTTP_REALITY,
    InboundChoice.VLESS_GRPC_REALITY,
    InboundChoice.SHADOWSOCKS,
)

# Каталог сертификатов внутри контейнера remnanode (точка монтирования из
# compose-шаблона). На хосте им управляет issue_cert.yml; xray внутри контейнера
# видит сертификат именно по этому пути, поэтому cert_file/key_file для
# build_profile строим от него, а не от хост-пути.
NODE_CERT_DIR_CONTAINER = "/etc/remnanode/certs"

# Поллинг статуса ноды после регистрации.
POLL_ATTEMPTS = 36          # 36 × 5с = 3 минуты
POLL_INTERVAL_SEC = 5.0


def _cert_paths(domain_name: str) -> tuple[str, str]:
    """Пути сертификата и ключа внутри контейнера для данного домена.
    Совпадают с тем, куда issue_cert.yml кладёт fullchain.pem/key.pem."""
    base = f"{NODE_CERT_DIR_CONTAINER}/{domain_name}"
    return f"{base}/fullchain.pem", f"{base}/key.pem"


class ProvisionError(Exception):
    """Шаг конвейера завершился неуспехом. detail — для отчёта оператору."""


def _default_make_client(panel_url: str, api_token: str) -> RemnawaveClient:
    return RemnawaveClient(panel_url, api_token)


async def _noop_report(state: NodeState, detail: str) -> None:
    """Заглушка отчёта: по умолчанию просто лог. Реальную доставку статусов в
    Telegram/веб и запись в БД подключает вызывающий код через ProvisionDeps."""
    logger.info("state=%s %s", state.value, detail)


@dataclass
class ProvisionDeps:
    """Швы конвейера. По умолчанию — боевые реализации, в тестах — фейки."""

    bootstrap_password: Callable[..., Awaitable[ssh_bootstrap.BootstrapResult]] = (
        ssh_bootstrap.bootstrap_password
    )
    bootstrap_key: Callable[..., Awaitable[ssh_bootstrap.BootstrapResult]] = (
        ssh_bootstrap.bootstrap_key
    )
    run_playbook: Callable[..., Awaitable[ansible_runner.PlaybookResult]] = (
        ansible_runner.run_playbook
    )
    build_profile: Callable[..., xray_config.GeneratedProfile] = xray_config.build_profile
    check_domain: Callable[[str, str], Awaitable[domain.DomainCheck]] = (
        domain.check_points_to
    )
    make_client: Callable[[str, str], RemnawaveClient] = _default_make_client
    vault_put: Callable[[str, dict], Any] | None = None
    report: Callable[[NodeState, str], Awaitable[None]] = _noop_report
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    poll_attempts: int = POLL_ATTEMPTS
    poll_interval_sec: float = POLL_INTERVAL_SEC


class _Pipeline:
    """Прогон одной задачи провижининга с контролем переходов состояний.

    Каждый значимый шаг сопровождается переходом state-машины и отчётом. Любой
    шаг, кинувший ProvisionError, переводит задачу в FAILED — необратимых
    действий до проверки рабочего состояния не делаем (принцип «не навреди»).
    """

    def __init__(self, payload: dict, deps: ProvisionDeps) -> None:
        self.p = payload
        self.deps = deps
        self.state = NodeState.QUEUED

    async def _advance(self, dst: NodeState, detail: str) -> None:
        """Перейти в новое состояние, если переход разрешён, и отчитаться."""
        if not can_transition(self.state, dst):
            raise ProvisionError(
                f"недопустимый переход {self.state.value} → {dst.value}"
            )
        self.state = dst
        await self.deps.report(dst, detail)

    def _inbound_choices(self) -> list[InboundChoice]:
        """Выбор inbound'ов: из payload, иначе дефолтный domain-free набор."""
        raw = self.p.get("inbounds")
        if not raw:
            return list(DEFAULT_INBOUNDS)
        try:
            return [InboundChoice(v) for v in raw]
        except ValueError as exc:
            raise ProvisionError(f"неизвестный inbound в payload: {exc}") from exc

    async def _bootstrap(self) -> str:
        """Детекция + перевод сервера на ключ. Возвращает приватный ключ."""
        ip = self.p["ip"]
        login = self.p["login"]
        auth = self.p["auth"]
        await self._advance(NodeState.BOOTSTRAPPING, f"Подключаюсь к {ip} ({auth})")

        if auth == "password":
            result = await self.deps.bootstrap_password(
                ip, login, self.p["password"]
            )
        elif auth == "key":
            result = await self.deps.bootstrap_key(
                ip, login, self.p["private_key"]
            )
        else:
            raise ProvisionError(f"неизвестный способ доступа: {auth!r}")

        if not result.ok or not result.private_key:
            raise ProvisionError(result.detail or "bootstrap не удался")
        return result.private_key

    def _store_key(self, ip: str, private_key: str) -> None:
        """Положить приватный ключ в Vault. В БД пишется только путь (vault_path),
        сам ключ — никогда (см. db/models.py, секреты только в Vault)."""
        if self.deps.vault_put is None:
            return
        self.deps.vault_put(f"nodes/{ip}/ssh", {"private_key": private_key})

    async def _setup_tls(
        self, ip: str, login: str, private_key: str, choices: list[InboundChoice]
    ) -> tuple[str | None, str | None, str | None]:
        """Подготовить TLS, если среди выбранных есть домен-инбаунд (ADR 0005).

        Возвращает (domain, cert_file, key_file) для build_profile, либо тройку
        None для domain-free набора. Сначала гейт резолва (домен уже должен
        указывать на ноду), затем выпуск сертификата по HTTP-01 — необратимого
        тут нет, но без рабочего домена выпуск бессмысленен (принцип «не навреди»).
        """
        if not any(c in TLS_CHOICES for c in choices):
            return None, None, None

        raw = self.p.get("tls_domain")
        if not raw:
            raise ProvisionError("для TLS-инбаунда нужен домен (tls_domain не задан)")
        domain_name = domain.normalize_domain(raw)

        await self.deps.report(
            self.state, f"Проверяю, что {domain_name} указывает на {ip}"
        )
        check = await self.deps.check_domain(domain_name, ip)
        if not check.ok:
            raise ProvisionError(check.detail)

        await self.deps.report(self.state, f"Выпускаю сертификат для {domain_name}")
        cert = await self.deps.run_playbook(
            ansible_runner.ISSUE_CERT_PLAYBOOK,
            ip,
            login,
            private_key,
            extra_vars={
                "cert_domain": domain_name,
                "cert_email": self.p.get("cert_email", ""),
            },
        )
        if not cert.ok:
            raise ProvisionError(cert.detail)

        cert_file, key_file = _cert_paths(domain_name)
        return domain_name, cert_file, key_file

    async def _open_inbound_ports(
        self, ip: str, login: str, private_key: str,
        generated: xray_config.GeneratedProfile,
    ) -> None:
        """Открыть в UFW порты занятые выбранными inbound'ами (ADR 0005).

        Открываем ровно те порты, что генератор раздал inbound'ам, а не весь
        пул фолбэков. Порт 80 для ACME здесь не трогаем — его открывает
        issue_cert.yml и только для TLS-набора (для domain-free 80 не нужен).
        """
        ports = sorted(set(generated.ports.values()))
        if not ports:
            raise ProvisionError("генератор не вернул портов inbound'ов")

        await self.deps.report(self.state, f"Открываю порты в UFW: {ports}")
        result = await self.deps.run_playbook(
            ansible_runner.OPEN_PORTS_PLAYBOOK,
            ip,
            login,
            private_key,
            extra_vars={"inbound_ports": ports},
        )
        if not result.ok:
            raise ProvisionError(result.detail)

    async def _run(self) -> NodeConnState:
        ip = self.p["ip"]
        login = self.p["login"]

        if self.p.get("panel_mode") == "new":
            # Разворот панели с нуля — отдельный флоу (ADR 0001), не этот конвейер.
            raise ProvisionError(
                "разворот новой панели здесь не поддержан: ожидается готовая панель"
            )

        panel_url = self.p.get("panel_url") or settings.remnawave_panel_url
        panel_token = self.p.get("panel_token") or settings.remnawave_api_token
        if not panel_url or not panel_token:
            raise ProvisionError("не заданы URL/токен панели")

        # 1. Bootstrap: сервер переходит на ключевую аутентификацию.
        private_key = await self._bootstrap()
        self._store_key(ip, private_key)

        # 2. Provisioning: hardening + разворот контейнера ноды.
        await self._advance(NodeState.PROVISIONING, "Настраиваю сервер")

        hardening = await self.deps.run_playbook(
            ansible_runner.HARDENING_PLAYBOOK, ip, login, private_key
        )
        if not hardening.ok:
            raise ProvisionError(hardening.detail)

        # TLS-инбаунды (ADR 0005): домен обязан уже указывать на ноду, после чего
        # выпускаем сертификат по HTTP-01. Делаем это ДО deploy_node, чтобы
        # сертификат лежал в монтируемом каталоге к моменту старта контейнера.
        # Для domain-free набора шаг пропускается и пути остаются None.
        choices = self._inbound_choices()
        tls_domain, cert_file, key_file = await self._setup_tls(
            ip, login, private_key, choices
        )

        # Профиль собираем здесь, до deploy_node: из него берём раскладку портов,
        # чтобы открыть их в UFW прежде, чем нода начнёт принимать трафик. Сам
        # config уйдёт в панель ниже, на шаге REGISTERING.
        generated = self.deps.build_profile(
            choices,
            tls_domain=tls_domain,
            cert_file=cert_file,
            key_file=key_file,
        )

        # hardening поставил default deny + только 22; теперь разрешаем порты
        # выбранных inbound'ов, иначе трафик до ноды не дойдёт. Делаем до старта
        # контейнера, чтобы он поднимался уже за открытым firewall'ом.
        await self._open_inbound_ports(ip, login, private_key, generated)

        # Нода доверяет панели по её публичному ключу (ADR 0004): кладём его в
        # SSL_CERT контейнера. Порт ноды задаём сами — он же уйдёт в create_node.
        client = self.deps.make_client(panel_url, panel_token)
        panel_pubkey = await client.get_panel_pubkey()

        deploy = await self.deps.run_playbook(
            ansible_runner.DEPLOY_NODE_PLAYBOOK,
            ip,
            login,
            private_key,
            extra_vars={
                "remnanode_secret_key": panel_pubkey,
                "remnanode_port": NODE_APP_PORT,
            },
        )
        if not deploy.ok:
            raise ProvisionError(deploy.detail)

        # 3. Registering: профиль конфигурации → нода.
        await self._advance(NodeState.REGISTERING, "Регистрирую ноду в панели")

        # Панель сама присваивает inbound'ам uuid'ы; связываем по тегам (ADR 0006).
        profile = await client.create_config_profile(f"node-{ip}", generated.config)
        active_inbounds = [
            profile.tag_to_inbound[tag]
            for tag in generated.tags
            if tag in profile.tag_to_inbound
        ]
        if not active_inbounds:
            raise ProvisionError("панель не вернула ни одного inbound по нашим тегам")

        node = await client.create_node(
            name=f"node-{ip}",
            address=ip,
            config_profile_uuid=profile.uuid,
            active_inbounds=active_inbounds,
            port=NODE_APP_PORT,
            country_code=self.p.get("country_code", "XX"),
        )

        # 4. Поллинг до online.
        status = await self._poll_until_online(client, node.uuid)
        await self._advance(NodeState.ONLINE, "Нода online")
        return status

    async def _poll_until_online(
        self, client: RemnawaveClient, node_uuid: str
    ) -> NodeConnState:
        """Опрашивать статус ноды до ONLINE или до исчерпания попыток."""
        last = NodeConnState.OFFLINE
        for attempt in range(1, self.deps.poll_attempts + 1):
            last = await client.get_node_status(node_uuid)
            if last is NodeConnState.ONLINE:
                return last
            if last is NodeConnState.DISABLED:
                raise ProvisionError("нода зарегистрирована, но выключена в панели")
            await self.deps.report(
                self.state,
                f"Жду подключения ноды ({attempt}/{self.deps.poll_attempts}): "
                f"{last.value}",
            )
            await self.deps.sleep(self.deps.poll_interval_sec)
        raise ProvisionError(
            f"нода не вышла online за {self.deps.poll_attempts} попыток "
            f"(последний статус: {last.value})"
        )

    async def execute(self) -> None:
        try:
            await self._run()
        except ProvisionError as exc:
            await self._fail(str(exc))
        except Exception as exc:  # noqa: BLE001 — непредвиденное тоже не должно ронять воркер
            logger.exception("provision_node: непредвиденный сбой")
            await self._fail(f"внутренняя ошибка: {exc}")

    async def _fail(self, detail: str) -> None:
        """Перевести задачу в FAILED и отчитаться. Переход в FAILED разрешён из
        любого рабочего состояния (см. statemachine.TRANSITIONS)."""
        if can_transition(self.state, NodeState.FAILED):
            self.state = NodeState.FAILED
        await self.deps.report(NodeState.FAILED, detail)


def build_production_deps(ctx: dict, payload: dict) -> ProvisionDeps:
    """Собрать боевые зависимости для одной задачи.

    В дефолтном ProvisionDeps боевые уже все швы, кроме двух, которым нужен
    контекст задачи и внешние сервисы: `report` (привязан к node_id/chat_id,
    пишет в БД и шлёт в Telegram) и `vault_put` (приватный ключ → Vault). Их и
    достраиваем здесь.

    Bot и фабрика сессий берутся из ctx воркера (см. WorkerSettings.on_startup),
    node_id/chat_id — из payload, поставленного ботом.
    """
    from db import get_sessionmaker
    from db.repo import record_status
    from secretstore.vault import VaultStore

    node_id = payload.get("node_id")
    chat_id = payload.get("chat_id")
    bot = ctx.get("bot")

    if node_id is None:
        # Без node_id обновлять в БД нечего — оставляем лог-заглушку.
        return ProvisionDeps(vault_put=VaultStore().put)

    session_factory = get_sessionmaker()

    async def persist(nid: int, state: str, detail: str) -> None:
        await record_status(session_factory, nid, state, detail)

    notify = None
    if bot is not None:
        async def notify(cid: int, text: str) -> None:  # noqa: F811
            await bot.send_message(cid, text)

    report = reporting.make_reporter(
        node_id, chat_id, persist=persist, notify=notify
    )
    return ProvisionDeps(report=report, vault_put=VaultStore().put)


async def provision_node(ctx: dict, payload: dict) -> None:
    """Полный цикл провижининга ноды.

    payload (из FSM-диалога бота): ip, login, auth (password|key) и либо password,
    либо private_key; node_id и chat_id для отчётности; опционально
    panel_url/panel_token, inbounds, country_code, tls_domain.
    Пароль живёт только в payload задачи и стирается в bootstrap; в БД он не пишется.

    Зависимости берутся из ctx["deps"] (ProvisionDeps) — это путь тестов; в проде
    их там нет, и собираются боевые через build_production_deps.
    """
    deps = ctx.get("deps") or build_production_deps(ctx, payload)
    await _Pipeline(payload, deps).execute()


async def _worker_startup(ctx: dict) -> None:
    """Поднять общие на воркер ресурсы: Telegram-бот и таблицы БД."""
    from aiogram import Bot

    from db import init_models

    ctx["bot"] = Bot(token=settings.bot_token)
    await init_models()


async def _worker_shutdown(ctx: dict) -> None:
    bot = ctx.get("bot")
    if bot is not None:
        await bot.session.close()


class WorkerSettings:
    functions = [provision_node]
    on_startup = _worker_startup
    on_shutdown = _worker_shutdown
    redis_settings = RedisSettings(host=settings.redis_host,
                                   port=settings.redis_port)
