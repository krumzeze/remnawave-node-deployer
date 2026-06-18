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

from arq import cron
from arq.connections import RedisSettings

from config import settings
from orchestrator import (
    ansible_runner,
    domain,
    local_compose,
    monitor,
    panel_setup,
    panel_stack,
    reporting,
    ssh_bootstrap,
    xray_config,
)
from orchestrator.remnawave_client import NodeConnState, RemnawaveClient
from orchestrator.statemachine import NodeState, can_transition
from orchestrator.xray_config import TLS_CHOICES, InboundChoice

logger = logging.getLogger(__name__)


def _panel_name(ip: str) -> str:
    """Имя для панели из IP. Панель валидирует имена по `^[A-Za-z0-9_\\s-]+$`,
    точки в IP под этот паттерн не подходят — заменяем их на дефис, чтобы
    получить, например, `node-2-26-67-180`."""
    return "node-" + ip.replace(".", "-")

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


# Имена host'ов, которые пользователь видит в подписке (ADR 0008). Формат
# remark — «<флаг> <страна> · <Отпечаток>», например «🇳🇱 Нидерланды · Firefox»:
# флаг и название страны выводим из ISO-2 кода ноды, отпечаток — uTLS-fingerprint
# инбаунда. Имя самой ноды в панели при этом не трогаем — это отдельная сущность.
HOST_REMARK_MAXLEN = 40

# RU-названия стран по ISO-2. Таблица не претендует на полноту: покрывает
# частые для VPS направления, для остального фолбэк — сам код (лучше пустоты).
_COUNTRY_NAMES_RU: dict[str, str] = {
    "NL": "Нидерланды", "DE": "Германия", "FR": "Франция", "GB": "Великобритания",
    "US": "США", "CA": "Канада", "FI": "Финляндия", "SE": "Швеция",
    "NO": "Норвегия", "PL": "Польша", "CZ": "Чехия", "AT": "Австрия",
    "CH": "Швейцария", "IT": "Италия", "ES": "Испания", "PT": "Португалия",
    "IE": "Ирландия", "BE": "Бельгия", "LU": "Люксембург", "DK": "Дания",
    "EE": "Эстония", "LV": "Латвия", "LT": "Литва", "RO": "Румыния",
    "BG": "Болгария", "HU": "Венгрия", "GR": "Греция", "TR": "Турция",
    "UA": "Украина", "RU": "Россия", "KZ": "Казахстан", "AM": "Армения",
    "GE": "Грузия", "AE": "ОАЭ", "IL": "Израиль", "IN": "Индия",
    "SG": "Сингапур", "JP": "Япония", "KR": "Южная Корея", "HK": "Гонконг",
    "AU": "Австралия", "BR": "Бразилия", "ZA": "ЮАР",
}


def _country_flag(code: str) -> str:
    """Эмодзи-флаг из ISO-2 через regional indicator symbols (A→🇦 и т.д.).
    Для некорректного кода (не две латинские буквы) — пустая строка."""
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha() or not code.isascii():
        return ""
    return "".join(chr(0x1F1E6 + (ord(ch) - ord("A"))) for ch in code)


def _host_remark(country_code: str, fingerprint: str | None) -> str:
    """Человекочитаемый remark host'а: «<флаг> <страна> · <Отпечаток>».

    Без отпечатка (например, Shadowsocks — там uTLS нет) хвост «· …» опускаем,
    остаётся «<флаг> <страна>». Для неизвестного кода страны название = сам код.
    Длину режем под лимит панели (HOST_REMARK_MAXLEN)."""
    code = (country_code or "XX").strip().upper()
    name = _COUNTRY_NAMES_RU.get(code, code)
    flag = _country_flag(code)
    label = f"{flag} {name}".strip()
    if fingerprint:
        label = f"{label} · {fingerprint.capitalize()}"
    return label[:HOST_REMARK_MAXLEN]


def _host_exists(existing, inbound_uuid: str, address: str, port: int) -> bool:
    """Есть ли среди существующих хостов панели дубль для этого инбаунда.

    Надёжный минимум сверки — совпадение address+port (в нём один инбаунд = один
    хост). Если у хоста доступен uuid инбаунда, дополнительно требуем, чтобы он
    совпал: один адрес+порт может нести разные инбаунды (например, разные
    сети по тому же порту). Если uuid инбаунда недоступен (None), полагаемся
    только на address+port."""
    for h in existing:
        if h.address != address or h.port != port:
            continue
        if h.inbound_uuid is not None and h.inbound_uuid != str(inbound_uuid):
            continue
        return True
    return False


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
    vault_get: Callable[[str], dict] | None = None
    # Удаление транзитного bootstrap-секрета из Vault после успешного перехода
    # на ключ. None — шаг пропускается (например, в тестах без проверки стирания).
    vault_delete: Callable[[str], Any] | None = None
    # Запись uuid ноды/пути ключа в строку Node. Привязан к node_id, поэтому
    # достраивается в build_production_deps; по умолчанию None — шаг пропускается.
    persist_node: Callable[..., Awaitable[None]] | None = None
    report: Callable[[NodeState, str], Awaitable[None]] = _noop_report
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    poll_attempts: int = POLL_ATTEMPTS
    poll_interval_sec: float = POLL_INTERVAL_SEC

    # --- Швы разворота панели с нуля (provision_panel, ADR 0001). ---
    # Регистрация админа + выпуск API-токена панели через HTTP. По умолчанию —
    # боевой поток на httpx; в тестах фейк без сети.
    provision_panel_admin: Callable[..., Awaitable[str]] = (
        panel_setup.provision_panel_admin
    )
    # Фабрика локального compose (вариант «local»): (base_dir) → LocalCompose.
    # По умолчанию боевая; в тестах подменяется фейком без docker.
    make_local_compose: Callable[[str], local_compose.LocalCompose] = (
        local_compose.LocalCompose
    )
    # Запись Panel/токена панели после успешного разворота (привязана к owner,
    # достраивается в build_panel_deps). None — шаг пропускается.
    persist_panel: Callable[..., Awaitable[None]] | None = None


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

    def _key_vault_path(self) -> str | None:
        """Путь приватного ключа ноды в Vault — по node_id, не по IP.

        Адресация по node_id разводит ноды с одним IP (переиспользованный VPS
        или повторное добавление): они больше не делят и не перетирают ключ.
        node_id есть в payload; если его (теоретически) нет — фолбэк на IP, чтобы
        хотя бы сохранить ключ, а не потерять его молча."""
        node_id = self.p.get("node_id")
        if node_id is not None:
            return f"nodes/{node_id}/ssh"
        ip = self.p.get("ip")
        return f"nodes/{ip}/ssh" if ip else None

    def _load_stored_key(self) -> str | None:
        """Достать ранее сохранённый приватный ключ ноды из Vault.

        Ключ туда кладёт `_store_key` после первого успешного bootstrap. Если
        Vault недоступен, пути нет или ключ пуст — возвращаем None и идём по
        обычной развилке. Любая ошибка чтения не должна ронять провижн, поэтому
        ловим широко."""
        path = self._key_vault_path()
        if self.deps.vault_get is None or path is None:
            return None
        try:
            data = self.deps.vault_get(path)
        except Exception:  # noqa: BLE001 — нет ключа/Vault недоступен → просто без resume
            return None
        key = (data or {}).get("private_key")
        return key or None

    def _panel_token(self) -> str | None:
        """Токен панели из Vault по panel_token_vault_path (panels/{owner}/token).

        В payload токена нет — туда кладётся только путь. Если путь не задан или
        Vault недоступен — возвращаем None, выше сработает фолбэк на
        settings.remnawave_api_token."""
        path = self.p.get("panel_token_vault_path")
        if self.deps.vault_get is None or not path:
            return None
        try:
            data = self.deps.vault_get(path)
        except Exception:  # noqa: BLE001 — нет токена/Vault недоступен → фолбэк на settings
            return None
        return (data or {}).get("token") or None

    def _read_bootstrap_secret(self) -> dict:
        """Прочитать транзитный bootstrap-секрет из Vault по secret_vault_path.

        В payload секрета нет — там только путь (см. build_payload бота). По пути
        лежит {"auth": ..., "password"|"private_key": ...}. Без vault_get или без
        пути читать неоткуда — это конфигурационная ошибка постановки задачи."""
        path = self.p.get("secret_vault_path")
        if self.deps.vault_get is None or not path:
            raise ProvisionError("нет доступа к секрету bootstrap (secret_vault_path)")
        try:
            data = self.deps.vault_get(path)
        except Exception as exc:  # noqa: BLE001 — нет секрета/Vault недоступен
            raise ProvisionError(f"секрет bootstrap недоступен: {exc}") from exc
        return data or {}

    def _drop_bootstrap_secret(self) -> None:
        """Стереть транзитный bootstrap-секрет из Vault — он больше не нужен.

        Best-effort: ошибка удаления (нет пути, Vault недоступен) не должна
        валить уже состоявшийся провижн, только логируем."""
        path = self.p.get("secret_vault_path")
        if self.deps.vault_delete is None or not path:
            return
        try:
            self.deps.vault_delete(path)
        except Exception:  # noqa: BLE001 — удаление транзита не критично для провижина
            logger.exception("не удалось стереть транзитный секрет bootstrap")

    async def _bootstrap(self) -> str:
        """Детекция + перевод сервера на ключ. Возвращает приватный ключ.

        Доступ-секрет (пароль или ключ) берём из Vault по secret_vault_path, а
        не из payload — в payload его нет. После успешного перехода на ключ
        транзитный секрет больше не нужен и стирается из Vault.

        Resume (ADR 0002, «не навреди»): если для этой ноды (по node_id) уже есть
        ключ в Vault (прошлый bootstrap прошёл), сервер уже переведён на ключ и
        пароль на нём, скорее всего, отключён. Тогда заходим сохранённым ключом и
        пропускаем перевод на ключ — это и делает повторный провижн (ретрай после
        сбоя на более позднем шаге) самодостаточным: секрет вводить повторно не
        нужно. Ключ перед использованием проверяется внутри bootstrap_key; если
        не подошёл — откатываемся на заданный способ доступа."""
        ip = self.p["ip"]
        login = self.p["login"]
        auth = self.p["auth"]
        await self._advance(NodeState.BOOTSTRAPPING, f"Подключаюсь к {ip} ({auth})")

        stored_key = self._load_stored_key()
        if stored_key:
            await self.deps.report(
                self.state, "Нашёл сохранённый ключ ноды — захожу по нему"
            )
            result = await self.deps.bootstrap_key(ip, login, stored_key)
            if result.ok and result.private_key:
                self._drop_bootstrap_secret()
                return result.private_key
            await self.deps.report(
                self.state,
                "Сохранённый ключ не подошёл — пробую заданный способ доступа",
            )

        secret = self._read_bootstrap_secret()
        if auth == "password":
            result = await self.deps.bootstrap_password(
                ip, login, secret.get("password", "")
            )
        elif auth == "key":
            result = await self.deps.bootstrap_key(
                ip, login, secret.get("private_key", "")
            )
        else:
            raise ProvisionError(f"неизвестный способ доступа: {auth!r}")

        if not result.ok or not result.private_key:
            raise ProvisionError(result.detail or "bootstrap не удался")
        self._drop_bootstrap_secret()
        return result.private_key

    def _store_key(self, private_key: str) -> None:
        """Положить приватный ключ в Vault по пути ноды (node_id). В БД пишется
        только путь (vault_path), сам ключ — никогда (см. db/models.py, секреты
        только в Vault). Если путь не определить (нет ни node_id, ни ip) — store
        пропускаем, ронять провижн из-за этого не стоит."""
        path = self._key_vault_path()
        if self.deps.vault_put is None or path is None:
            return
        self.deps.vault_put(path, {"private_key": private_key})

    async def _persist_node(
        self, *, remnawave_uuid: str | None = None,
        ssh_key_vault_path: str | None = None,
    ) -> None:
        """Записать в БД uuid ноды / путь ключа, если шов задан (best-effort).

        Сбой записи не должен валить провижн — он уже сделал необратимое; логируем
        и идём дальше, ровно как report."""
        if self.deps.persist_node is None:
            return
        try:
            await self.deps.persist_node(
                remnawave_uuid=remnawave_uuid,
                ssh_key_vault_path=ssh_key_vault_path,
            )
        except Exception:  # noqa: BLE001 — запись метаданных не критична для провижина
            logger.exception("persist_node: не удалось записать поля ноды")

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

        # Shadowsocks слушает ещё и udp (network: tcp,udp в конфиге) — открываем
        # udp только его порту, остальным inbound'ам udp не нужен. Список udp-портов
        # отдаёт генератор (теги несут per-node суффикс, опознать SS по тегу нельзя).
        udp_ports = sorted(set(generated.udp_ports))

        await self.deps.report(self.state, f"Открываю порты в UFW: {ports}")
        result = await self.deps.run_playbook(
            ansible_runner.OPEN_PORTS_PLAYBOOK,
            ip,
            login,
            private_key,
            extra_vars={"inbound_ports": ports, "inbound_udp_ports": udp_ports},
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
        panel_token = self._panel_token() or settings.remnawave_api_token
        if not panel_url or not panel_token:
            raise ProvisionError("не заданы URL/токен панели")

        # 1. Bootstrap: сервер переходит на ключевую аутентификацию.
        private_key = await self._bootstrap()
        self._store_key(private_key)
        key_path = self._key_vault_path()
        if key_path:
            await self._persist_node(ssh_key_vault_path=key_path)

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
        #
        # Донор Reality — per-node (ADR 0007): если оператор задал его в диалоге,
        # берём из payload, иначе дефолт генератора (иностранный сайт для ноды за
        # границей). server_names в payload приходит списком — приводим к кортежу.
        reality_dest = self.p.get("reality_dest") or xray_config.DEFAULT_REALITY_DEST
        reality_server_names = tuple(
            self.p.get("reality_server_names")
            or xray_config.DEFAULT_REALITY_SERVER_NAMES
        )
        generated = self.deps.build_profile(
            choices,
            reality_dest=reality_dest,
            reality_server_names=reality_server_names,
            tls_domain=tls_domain,
            cert_file=cert_file,
            key_file=key_file,
            # Per-node суффикс тегов: панель требует глобально уникальные теги
            # инбаундов, иначе вторая нода падает с 409 «same tag already exists».
            tag_suffix=ip.replace(".", "-"),
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
        profile = await client.create_config_profile(_panel_name(ip), generated.config)
        active_inbounds = [
            profile.tag_to_inbound[tag]
            for tag in generated.tags
            if tag in profile.tag_to_inbound
        ]
        if not active_inbounds:
            raise ProvisionError("панель не вернула ни одного inbound по нашим тегам")

        node = await client.create_node(
            name=_panel_name(ip),
            address=ip,
            config_profile_uuid=profile.uuid,
            active_inbounds=active_inbounds,
            port=NODE_APP_PORT,
            country_code=self.p.get("country_code", "XX"),
        )
        await self._persist_node(remnawave_uuid=node.uuid)

        # 3b. Публикация пользователям (ADR 0008): на каждый инбаунд заводим host
        # (строку подключения в подписке) и добавляем инбаунды в выбранные сквады.
        # Без этого нода дойдёт до online, но у пользователей не появится.
        await self._publish_to_users(
            client, ip, node.uuid, profile, active_inbounds, generated, tls_domain
        )

        # 4. Поллинг до online.
        status = await self._poll_until_online(client, node.uuid)
        await self._advance(NodeState.ONLINE, "Нода online")
        return status

    async def _publish_to_users(
        self,
        client: RemnawaveClient,
        ip: str,
        node_uuid: str,
        profile,
        active_inbounds: list[str],
        generated: xray_config.GeneratedProfile,
        tls_domain: str | None,
    ) -> None:
        """Завести host'ы и привязать инбаунды к сквадам (ADR 0008).

        На каждый выбранный инбаунд — один host. Адрес: для TLS-инбаунда домен
        ноды (под него выпущен сертификат), для остального — IP. Параметры
        (security/sni/path/fingerprint) берём из подсказок генератора, оператор
        их не вводит.

        Сквады: берём из payload (оператор выбрал в боте); если не заданы —
        дефолт «все сквады панели» (ADR 0008). Инбаунды дописываются к текущему
        составу сквада, существующие узлы не затрагиваются.
        """
        country_code = self.p.get("country_code", "XX")
        await self.deps.report(self.state, "Завожу хосты для подписки")

        # Дедуп при повторном провижене (как идемпотентность create_node и
        # create_config_profile): один раз читаем хосты панели и не создаём
        # дубль, если хост на этот инбаунд уже есть на том же адресе и порту.
        # Если листинг недоступен (пустой список — защитный фолбэк), поведение
        # прежнее: создаём всё. Сверяем по (address, port) как надёжному
        # минимуму, а где доступен — ещё и по uuid инбаунда.
        existing_hosts = await client.list_hosts()

        for tag in generated.tags:
            inbound_uuid = profile.tag_to_inbound.get(tag)
            if inbound_uuid is None:
                continue
            hint = generated.hosts.get(tag)
            security = hint.security if hint else "default"
            address = tls_domain if (security == "tls" and tls_domain) else ip
            port = generated.ports[tag]
            if _host_exists(existing_hosts, inbound_uuid, address, port):
                await self.deps.report(
                    self.state, f"Хост для {address}:{port} уже есть — пропускаю"
                )
                continue
            await client.create_host(
                inbound_uuid=inbound_uuid,
                config_profile_uuid=profile.uuid,
                remark=_host_remark(
                    country_code, hint.fingerprint if hint else None
                ),
                address=address,
                port=port,
                node_uuid=node_uuid,
                security=security,
                sni=hint.sni if hint else None,
                path=hint.path if hint else None,
                fingerprint=hint.fingerprint if hint else None,
            )

        squad_uuids = self.p.get("squad_uuids")
        if squad_uuids is None:
            squad_uuids = [s.uuid for s in await client.list_internal_squads()]
        if squad_uuids:
            await self.deps.report(
                self.state, "Добавляю ноду в выбранные сквады"
            )
            await client.add_inbounds_to_squads(squad_uuids, active_inbounds)

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
    from db.repo import record_status, set_node_fields
    from secretstore.vault import VaultStore

    node_id = payload.get("node_id")
    chat_id = payload.get("chat_id")
    bot = ctx.get("bot")

    vault = VaultStore()
    if node_id is None:
        # Без node_id обновлять в БД нечего — оставляем лог-заглушку.
        return ProvisionDeps(
            vault_put=vault.put, vault_get=vault.get, vault_delete=vault.delete,
        )

    session_factory = get_sessionmaker()

    async def persist(nid: int, state: str, detail: str) -> None:
        await record_status(session_factory, nid, state, detail)

    async def persist_node(
        *, remnawave_uuid: str | None = None,
        ssh_key_vault_path: str | None = None,
    ) -> None:
        await set_node_fields(
            session_factory, node_id,
            remnawave_uuid=remnawave_uuid,
            ssh_key_vault_path=ssh_key_vault_path,
        )

    notify = None
    if bot is not None:
        async def notify(cid: int, text: str) -> None:  # noqa: F811
            await bot.send_message(cid, text)

    report = reporting.make_reporter(
        node_id, chat_id, persist=persist, notify=notify
    )
    return ProvisionDeps(
        report=report, vault_put=vault.put, vault_get=vault.get,
        vault_delete=vault.delete, persist_node=persist_node,
    )


async def provision_node(ctx: dict, payload: dict) -> None:
    """Полный цикл провижининга ноды.

    payload (из FSM-диалога бота): ip, login, auth (password|key); node_id и
    chat_id для отчётности; secret_vault_path — путь к транзитному bootstrap-
    секрету в Vault ({"auth", "password"|"private_key"}), стираемому после
    bootstrap; panel_token_vault_path — путь к токену панели в Vault. Опционально
    panel_url, inbounds, country_code, tls_domain, reality_dest/
    reality_server_names (донор Reality, ADR 0007). Сами секреты в payload не
    лежат и в БД не пишутся — только пути в Vault.

    Зависимости берутся из ctx["deps"] (ProvisionDeps) — это путь тестов; в проде
    их там нет, и собираются боевые через build_production_deps.
    """
    deps = ctx.get("deps") or build_production_deps(ctx, payload)
    await _Pipeline(payload, deps).execute()


# ==========================================================================
# Разворот панели Remnawave с нуля (режим «new», ADR 0001).
# ==========================================================================
# Своя мини-пайплайн-логика, отдельная от provision_node: панель — это не нода,
# у неё другой набор шагов (свой стек compose + Caddy + регистрация админа) и
# другие отчётные статусы. State-машину нод тут не используем — прогресс
# показываем простыми текстовыми отчётами через тот же report-шов.

# Ожидание готовности панели после старта стека. Чуть длиннее, чем у ноды:
# первый старт тянет образы и гоняет миграции БД.
PANEL_READY_ATTEMPTS = 60
PANEL_READY_INTERVAL_SEC = 5.0


class _PanelPipeline:
    """Прогон разворота панели с нуля для одной задачи.

    payload (из мастера бота): owner, placement (vps|local), panel_domain,
    admin_username; admin_secret_vault_path — путь к транзитному паролю админа в
    Vault; для vps ещё ip/login/auth и secret_vault_path (доступ-секрет
    bootstrap, как у ноды). chat_id для отчётности. Сами пароли в payload не
    лежат — только пути в Vault.
    """

    def __init__(self, payload: dict, deps: ProvisionDeps) -> None:
        self.p = payload
        self.deps = deps

    async def _report(self, detail: str) -> None:
        # У панели нет state-машины нод; шлём прогресс как PROVISIONING — это
        # лишь канал доставки текста оператору (reporting сам подберёт заголовок).
        await self.deps.report(NodeState.PROVISIONING, detail)

    def _admin_password(self) -> str:
        """Пароль супер-админа из Vault по admin_secret_vault_path (транзит).

        В payload пароля нет — там только путь, как у bootstrap-секрета ноды.
        Без vault_get или пути читать неоткуда — это ошибка постановки задачи."""
        path = self.p.get("admin_secret_vault_path")
        if self.deps.vault_get is None or not path:
            raise ProvisionError("нет доступа к паролю админа (admin_secret_vault_path)")
        try:
            data = self.deps.vault_get(path)
        except Exception as exc:  # noqa: BLE001 — нет секрета/Vault недоступен
            raise ProvisionError(f"пароль админа недоступен: {exc}") from exc
        password = (data or {}).get("password")
        if not password:
            raise ProvisionError("в Vault нет пароля админа панели")
        return password

    def _drop_admin_secret(self) -> None:
        """Стереть транзитный пароль админа из Vault — он больше не нужен.

        Best-effort, как _drop_bootstrap_secret: ошибка удаления не должна валить
        уже состоявшийся разворот."""
        path = self.p.get("admin_secret_vault_path")
        if self.deps.vault_delete is None or not path:
            return
        try:
            self.deps.vault_delete(path)
        except Exception:  # noqa: BLE001 — удаление транзита не критично
            logger.exception("не удалось стереть транзитный пароль админа")

    def _read_bootstrap_secret(self) -> dict:
        """Транзитный доступ-секрет bootstrap для vps-разворота (как у ноды)."""
        path = self.p.get("secret_vault_path")
        if self.deps.vault_get is None or not path:
            raise ProvisionError("нет доступа к секрету bootstrap (secret_vault_path)")
        try:
            return self.deps.vault_get(path) or {}
        except Exception as exc:  # noqa: BLE001
            raise ProvisionError(f"секрет bootstrap недоступен: {exc}") from exc

    def _drop_bootstrap_secret(self) -> None:
        path = self.p.get("secret_vault_path")
        if self.deps.vault_delete is None or not path:
            return
        try:
            self.deps.vault_delete(path)
        except Exception:  # noqa: BLE001
            logger.exception("не удалось стереть транзитный секрет bootstrap панели")

    async def _bootstrap_vps(self) -> str:
        """Bootstrap сервера панели на ключ (ветка vps), переиспользуя швы ноды.

        Доступ-секрет берём из Vault по secret_vault_path. Возвращает приватный
        ключ для дальнейших ansible-прогонов. Здесь нет resume по node_id (панель
        — отдельная сущность); при повторе bootstrap_key/-password просто пройдёт
        заново, что безопасно (необратимое в bootstrap — только отключение пароля,
        идемпотентное)."""
        ip = self.p["ip"]
        login = self.p["login"]
        auth = self.p["auth"]
        secret = self._read_bootstrap_secret()
        if auth == "password":
            result = await self.deps.bootstrap_password(
                ip, login, secret.get("password", "")
            )
        elif auth == "key":
            result = await self.deps.bootstrap_key(
                ip, login, secret.get("private_key", "")
            )
        else:
            raise ProvisionError(f"неизвестный способ доступа: {auth!r}")
        if not result.ok or not result.private_key:
            raise ProvisionError(result.detail or "bootstrap панели не удался")
        self._drop_bootstrap_secret()
        return result.private_key

    def _panel_url(self) -> str:
        """URL панели для регистрации: https://<домен> (Caddy выпускает TLS)."""
        domain_name = self.p["panel_domain"]
        return f"https://{domain_name}"

    async def _deploy_vps(self, domain_name: str, secrets_: panel_stack.PanelSecrets) -> None:
        """Развернуть стек панели на отдельном VPS через ansible.

        Bootstrap → hardening (UFW) → deploy_panel.yml (docker + стек + Caddy +
        открытие 80/443). Секреты панели уходят в extra-vars, не в payload очереди.
        """
        ip = self.p["ip"]
        login = self.p["login"]
        await self._report(f"Подключаюсь к серверу панели {ip}")
        private_key = await self._bootstrap_vps()

        await self._report("Настраиваю сервер панели")
        hardening = await self.deps.run_playbook(
            ansible_runner.HARDENING_PLAYBOOK, ip, login, private_key
        )
        if not hardening.ok:
            raise ProvisionError(hardening.detail)

        await self._report("Разворачиваю стек панели (docker, Caddy, TLS)")
        deploy = await self.deps.run_playbook(
            ansible_runner.DEPLOY_PANEL_PLAYBOOK,
            ip,
            login,
            private_key,
            extra_vars={
                "panel_domain": domain_name,
                "panel_jwt_auth_secret": secrets_.jwt_auth_secret,
                "panel_jwt_api_tokens_secret": secrets_.jwt_api_tokens_secret,
                "panel_metrics_pass": secrets_.metrics_pass,
                "panel_postgres_password": secrets_.postgres_password,
            },
        )
        if not deploy.ok:
            raise ProvisionError(deploy.detail)

    async def _deploy_local(self, domain_name: str, secrets_: panel_stack.PanelSecrets) -> None:
        """Развернуть стек панели на хосте деплойера через docker-сокет хоста.

        Рендерим файлы стека и запускаем docker compose локально (без SSH). Шов
        make_local_compose в тестах — фейк без docker.
        """
        await self._report("Готовлю файлы стека панели на хосте деплойера")
        base_dir = self.p.get("panel_local_dir") or settings.panel_local_dir
        stack = self.deps.make_local_compose(base_dir)
        compose = panel_stack.render_compose()
        caddyfile = panel_stack.render_caddyfile(domain_name)
        env = panel_stack.render_env(domain_name, secrets_)
        cwd = stack.write_stack(compose, caddyfile, env)
        await self._report("Поднимаю стек панели (docker compose up)")
        try:
            stack.up(cwd)
        except local_compose.LocalComposeError as exc:
            raise ProvisionError(str(exc)) from exc

    async def _register_admin(self, panel_url: str) -> str:
        """Дождаться панели, зарегистрировать админа, выдать API-токен.

        Пароль админа читаем из Vault (транзит) и после успеха стираем — в логи
        и payload он не попадает. Возвращает долгоживущий токен панели.
        """
        await self._report("Жду готовности панели и регистрирую администратора")
        username = self.p["admin_username"]
        password = self._admin_password()
        try:
            token = await self.deps.provision_panel_admin(
                panel_url,
                username,
                password,
                sleep=self.deps.sleep,
                ready_attempts=PANEL_READY_ATTEMPTS,
                ready_interval_sec=PANEL_READY_INTERVAL_SEC,
            )
        except panel_setup.PanelSetupError as exc:
            raise ProvisionError(str(exc)) from exc
        finally:
            del password
        self._drop_admin_secret()
        return token

    async def _persist(self, panel_url: str, token: str) -> None:
        """Сохранить панель как обычную «существующую»: токен в Vault, Panel в БД.

        Дальше ноды добавляются текущим флоу (бот увидит сохранённую панель).
        Best-effort на запись в БД, как persist_node: сбой записи не отменяет
        уже развёрнутую панель.
        """
        if self.deps.persist_panel is None:
            return
        try:
            await self.deps.persist_panel(url=panel_url, token=token)
        except Exception:  # noqa: BLE001 — запись метаданных не критична
            logger.exception("persist_panel: не удалось сохранить панель")

    async def _run(self) -> None:
        placement = self.p.get("placement", "vps")
        domain_name = self.p["panel_domain"]
        secrets_ = panel_stack.PanelSecrets()

        if placement == "vps":
            await self._deploy_vps(domain_name, secrets_)
        elif placement == "local":
            await self._deploy_local(domain_name, secrets_)
        else:
            raise ProvisionError(f"неизвестное размещение панели: {placement!r}")

        panel_url = self._panel_url()
        token = await self._register_admin(panel_url)
        await self._persist(panel_url, token)
        await self._report(
            "Панель готова. Можно добавлять ноды — она уже сохранена."
        )

    async def execute(self) -> None:
        try:
            await self._run()
        except ProvisionError as exc:
            await self.deps.report(NodeState.FAILED, str(exc))
        except Exception as exc:  # noqa: BLE001 — непредвиденное не должно ронять воркер
            logger.exception("provision_panel: непредвиденный сбой")
            await self.deps.report(NodeState.FAILED, f"внутренняя ошибка: {exc}")


def build_panel_deps(ctx: dict, payload: dict) -> ProvisionDeps:
    """Боевые зависимости для разворота панели.

    Отличие от build_production_deps: отчёт привязан к chat_id (а не к node_id —
    у панели нет строки Node), и достраивается persist_panel (запись Panel в БД +
    токен в Vault по panels/{owner}/token). owner/chat_id берутся из payload.
    """
    from db import get_sessionmaker
    from db.repo import get_or_create_panel
    from secretstore.vault import VaultStore

    owner = payload.get("owner")
    chat_id = payload.get("chat_id")
    bot = ctx.get("bot")
    vault = VaultStore()

    notify = None
    if bot is not None:
        async def notify(cid: int, text: str) -> None:  # noqa: F811
            await bot.send_message(cid, text)

    async def report(state: NodeState, detail: str) -> None:
        # У панели нет node_id, поэтому в БД статус не пишем — только в чат.
        if notify is not None and chat_id is not None:
            try:
                await notify(chat_id, reporting.format_status(state, detail))
            except Exception:  # noqa: BLE001 — сбой Telegram не валит разворот
                logger.exception("provision_panel report: сбой доставки в чат")

    persist_panel = None
    if owner is not None:
        session_factory = get_sessionmaker()

        async def persist_panel(*, url: str, token: str) -> None:  # noqa: F811
            token_path = f"panels/{owner}/token"
            vault.put(token_path, {"token": token})
            await get_or_create_panel(
                session_factory, owner_tg_id=owner, url=url,
                token_vault_path=token_path,
            )

    return ProvisionDeps(
        report=report,
        vault_get=vault.get,
        vault_put=vault.put,
        vault_delete=vault.delete,
        persist_panel=persist_panel,
    )


async def provision_panel(ctx: dict, payload: dict) -> None:
    """Разворот панели Remnawave с нуля (режим «new», ADR 0001).

    payload (из мастера бота): owner, chat_id, placement (vps|local),
    panel_domain, admin_username; admin_secret_vault_path — путь к транзитному
    паролю админа в Vault; для vps — ip/login/auth и secret_vault_path
    (доступ-секрет bootstrap). Сами пароли в payload не лежат, только пути.

    Зависимости берутся из ctx["deps"] (тесты); в проде собираются боевые через
    build_panel_deps.
    """
    deps = ctx.get("deps") or build_panel_deps(ctx, payload)
    await _PanelPipeline(payload, deps).execute()


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
    """Конфиг arq-воркера: какие задачи обслуживаем и хуки жизненного цикла."""

    functions = [provision_node, provision_panel]
    # Фоновый поллер статуса нод (ADR 0013): каждые POLL_EVERY_MINUTES минут.
    # ctx воркера переживает запуски cron — в нём монитор держит счётчики offline.
    cron_jobs = [
        cron(
            monitor.poll_node_statuses,
            minute=set(range(0, 60, monitor.POLL_EVERY_MINUTES)),
            run_at_startup=False,
        )
    ]
    on_startup = _worker_startup
    on_shutdown = _worker_shutdown
    redis_settings = RedisSettings(host=settings.redis_host,
                                   port=settings.redis_port)
