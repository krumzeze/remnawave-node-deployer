"""Генератор Xray-конфига для config-profile панели (ADR 0005).

Деплойер сам создаёт профиль в панели (вариант «авто», без ручных действий
оператора): здесь собирается полный Xray-конфиг (`inbounds`/`outbounds`/
`routing`), который уходит в `CreateConfigProfileRequestDto.config`. Панель
разбирает `inbounds`, присваивает каждому свой uuid и tag и возвращает их —
дальше выбранные теги отображаются в uuid'ы для `create_node`.

Модуль намеренно чистый: никакой сети и SDK, только генерация ключей и сборка
JSON. Это нижний слой, его легко покрыть юнит-тестами.

Про маскировку Reality. `dest`/`serverNames` — это сайт-донор, под TLS которого
прячется хендшейк. Для ноды ЗА ГРАНИЦЕЙ донор должен быть иностранным сайтом на
TLS1.3+H2: у DPI есть сверка SNI с IP, и отечественный SNI (vk/yandex) на
зарубежном IP палит соединение, а не маскирует. Поэтому дефолт — внешний хост,
а конкретный донор задаётся per-node.

`clients`/пользователи в inbound НЕ кладутся: их подставляет сама Remnawave.
"""
from __future__ import annotations

import base64
import enum
import os
from dataclasses import dataclass, field

# Случайность берём из os.urandom — этого достаточно для ключей и паролей,
# и не зависим от stdlib-модуля по имени (исторически его перекрывал локальный
# пакет, теперь переименованный в secretstore).

# Донор Reality по умолчанию для зарубежной ноды: стабильный TLS1.3+H2, в РФ
# доступен, живёт на крупном CDN — несовпадение IP и SNI выглядит нормой.
DEFAULT_REALITY_DEST = "www.microsoft.com:443"
DEFAULT_REALITY_SERVER_NAMES = ("www.microsoft.com",)

# Метод Shadowsocks: AEAD-2022, ключ сервера выводим из 32 случайных байт.
DEFAULT_SS_METHOD = "2022-blake3-aes-256-gcm"

# uTLS-отпечаток клиента для host'ов reality/tls. firefox вместо chrome: на части
# нод в РФ chrome-отпечаток стал выбиваться DPI, firefox держится стабильнее.
DEFAULT_FINGERPRINT = "firefox"


class InboundChoice(str, enum.Enum):
    """Пункты меню inbound'ов из ADR 0005."""

    VLESS_REALITY_TCP = "vless-reality-tcp"      # domain-free
    VLESS_XHTTP_REALITY = "vless-xhttp-reality"  # domain-free
    VLESS_XHTTP_TLS = "vless-xhttp-tls"          # нужен домен
    VLESS_GRPC_REALITY = "vless-grpc-reality"    # domain-free
    TROJAN_WS_TLS = "trojan-ws-tls"              # нужен домен
    SHADOWSOCKS = "shadowsocks"                  # domain-free
    HYSTERIA2 = "hysteria2"                       # нужен домен, UDP/QUIC


# Какие варианты требуют домена и сертификата (ветка TLS в ADR 0005). Hysteria2
# здесь же: TLS у него обязателен (QUIC поверх TLS1.3), сертификат тот же, что и
# у прочих доменных инбаундов (acme.sh, см. _setup_tls в tasks.py).
TLS_CHOICES = frozenset(
    {
        InboundChoice.VLESS_XHTTP_TLS,
        InboundChoice.TROJAN_WS_TLS,
        InboundChoice.HYSTERIA2,
    }
)

# Какие варианты используют Reality и потому требуют генерации ключей.
REALITY_CHOICES = frozenset(
    {
        InboundChoice.VLESS_REALITY_TCP,
        InboundChoice.VLESS_XHTTP_REALITY,
        InboundChoice.VLESS_GRPC_REALITY,
    }
)

# Детерминированная раскладка портов без конфликтов: первый выбранный получает
# 443, остальные — фиксированные высокие порты по очереди. Так несколько
# inbound'ов уживаются на одной ноде (см. «Последствия» ADR 0005).
PORT_443 = 443
# Пул должен вмещать все типы инбаундов разом (дефолт «все»): 443 + фолбэки ≥
# числу пунктов меню, иначе раздача портов упрётся в исчерпание пула.
FALLBACK_PORTS = (8443, 8444, 2053, 2083, 2087, 2096)


def base_choice_from_tag(tag: str) -> InboundChoice | None:
    """Вытащить пункт меню из тега инбаунда профиля, либо None.

    Теги в профиле — это `<choice.value>` с per-node суффиксом (`vless-reality-
    tcp-1-2-3-4`), а у простых случаев — голый `choice.value`. Сопоставляем по
    точному совпадению или префиксу `value-`. Берём самое длинное совпадение,
    чтобы значения-префиксы не путались между собой (на случай будущих пунктов).
    """
    if not tag:
        return None
    best: InboundChoice | None = None
    for choice in InboundChoice:
        v = choice.value
        if tag == v or tag.startswith(v + "-"):
            if best is None or len(v) > len(best.value):
                best = choice
    return best


def available_choices_for_node(
    existing_tags: list[str], *, has_domain: bool
) -> list[InboundChoice]:
    """Какие инбаунды можно добавить к уже развёрнутой ноде.

    Отсеиваем: (1) те, что на ноде уже есть (по базовому тегу — повторno тот же
    инбаунд не заводим), (2) доменные (TLS/Hysteria2), если у ноды нет домена с
    сертификатом — без него такой инбаунд не поднять. has_domain выводится выше
    по стеку из того, есть ли среди существующих тегов хоть один доменный (тогда
    сертификат на ноде уже выпущен). Порядок — как в InboundChoice (стабильный
    для UI)."""
    present = {
        c for c in (base_choice_from_tag(t) for t in existing_tags) if c is not None
    }
    out: list[InboundChoice] = []
    for choice in InboundChoice:
        if choice in present:
            continue
        if choice in TLS_CHOICES and not has_domain:
            continue
        out.append(choice)
    return out


def used_ports(config: dict) -> set[int]:
    """Порты, занятые инбаундами Xray-конфига (профиля панели).

    Нужно и добавлению инбаунда к ноде, и повторному провижну: новые инбаунды
    не должны садиться на порт, который в профиле уже занят."""
    ports: set[int] = set()
    for inb in config.get("inbounds", []) or []:
        p = inb.get("port")
        if isinstance(p, int):
            ports.add(p)
    return ports


def _b64url_nopad(raw: bytes) -> str:
    """base64url без выравнивания — формат ключей, как у Xray (`x25519`)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class RealityKeys:
    """Пара ключей Reality и shortIds.

    `private_key` идёт в конфиг сервера; `public_key` сам Xray в серверный конфиг
    не пишет — он нужен клиенту/подписке, поэтому держим его рядом для будущего
    заведения host'ов (вне MVP, но генерим сразу, чтобы не считать второй раз).
    """

    private_key: str
    public_key: str
    short_ids: list[str]


@dataclass
class HostHint:
    """Параметры для заведения host'а на инбаунд (ADR 0008).

    Хост — это то, что панель отдаёт в подписку пользователю. Все поля выводятся
    из того, как мы собрали инбаунд, поэтому оператор их не вводит. security —
    доменная строка («reality»/«tls»/«none»), её мапит на SecurityLayer клиент.
    sni для Reality — это сайт-донор (serverName), для TLS — домен ноды. path —
    для ws/xhttp путь, для grpc — serviceName; для остальных None.
    """

    security: str
    network: str
    sni: str | None = None
    path: str | None = None
    fingerprint: str | None = None


@dataclass
class GeneratedProfile:
    """Результат сборки профиля.

    `config` уходит как есть в `create_config_profile`. `reality_keys` — по тегу
    inbound'а, для последующего построения клиентских ссылок. `tags` — порядок
    тегов, как они легли в конфиг (для маппинга tag→uuid после ответа панели).
    """

    config: dict
    tags: list[str]
    reality_keys: dict[str, RealityKeys] = field(default_factory=dict)
    # Раскладка портов tag→port: какой inbound на каком порту сел. Нужна выше по
    # стеку, чтобы открыть в UFW ровно занятые порты, а не весь пул вслепую.
    ports: dict[str, int] = field(default_factory=dict)
    # Подсказки для заведения host'ов: tag→HostHint (ADR 0008).
    hosts: dict[str, HostHint] = field(default_factory=dict)
    # Порты, которые слушаются ещё и по UDP (Shadowsocks). Держим отдельным
    # списком, а не вычисляем из тегов: теги теперь несут per-node суффикс, и
    # сравнивать их со значением InboundChoice больше нельзя.
    udp_ports: list[int] = field(default_factory=list)


# Раскладка транспорта/безопасности по пунктам меню: из неё строятся host'ы.
# Держим отдельной таблицей, а не вытаскиваем из готового streamSettings, чтобы
# host-подсказка не зависела от формата Xray-конфига.
_HOST_SHAPE: dict[InboundChoice, dict] = {
    InboundChoice.VLESS_REALITY_TCP: {"security": "reality", "network": "tcp"},
    InboundChoice.VLESS_XHTTP_REALITY: {"security": "reality", "network": "xhttp", "path": "/"},
    InboundChoice.VLESS_GRPC_REALITY: {"security": "reality", "network": "grpc", "path": "grpc"},
    InboundChoice.VLESS_XHTTP_TLS: {"security": "tls", "network": "xhttp", "path": "/"},
    InboundChoice.TROJAN_WS_TLS: {"security": "tls", "network": "ws", "path": "/"},
    InboundChoice.SHADOWSOCKS: {"security": "none", "network": "tcp"},
    InboundChoice.HYSTERIA2: {"security": "tls", "network": "hysteria"},
}


def _host_hint(choice: InboundChoice, *, server_names: list[str],
               tls_domain: str | None) -> HostHint:
    """Собрать HostHint для инбаунда: sni и fingerprint зависят от security."""
    shape = _HOST_SHAPE[choice]
    security = shape["security"]
    # uTLS-отпечаток: firefox. chrome в РФ сейчас выбивается DPI на ряде нод,
    # firefox-отпечаток работает стабильнее — поэтому он дефолт для reality/tls.
    if security == "reality":
        sni = server_names[0] if server_names else None
        fingerprint = DEFAULT_FINGERPRINT
    elif security == "tls":
        sni = tls_domain
        # Hysteria2 — это QUIC, у него нет uTLS-отпечатка (fingerprint), он
        # относится только к TCP-TLS клиентам. Для остальных TLS-инбаундов — firefox.
        fingerprint = None if choice is InboundChoice.HYSTERIA2 else DEFAULT_FINGERPRINT
    else:
        sni = None
        fingerprint = None
    return HostHint(
        security=security,
        network=shape["network"],
        sni=sni,
        path=shape.get("path"),
        fingerprint=fingerprint,
    )


def host_hint_for_existing_inbound(inbound: dict) -> HostHint | None:
    """Восстановить HostHint по инбаунду, уже лежащему в профиле панели.

    Нужно повторному провижну: инбаунд в профиле есть, а host для него мог не
    завестись (провижн оборвался). Параметры хоста восстанавливаем из самого
    инбаунда — sni Reality из его serverNames (донор мог быть кастомным), домен
    TLS из tlsSettings, — а не из дефолтов генератора. Для неопознаваемого тега
    возвращаем None."""
    choice = base_choice_from_tag(inbound.get("tag") or "")
    if choice is None:
        return None
    ss = inbound.get("streamSettings") or {}
    server_names = list((ss.get("realitySettings") or {}).get("serverNames") or [])
    tls_domain = (ss.get("tlsSettings") or {}).get("serverName")
    return _host_hint(choice, server_names=server_names, tls_domain=tls_domain)


def generate_reality_keys(*, short_id_count: int = 3) -> RealityKeys:
    """Сгенерировать x25519-пару и набор shortIds для Reality.

    shortId в Xray — это hex чётной длины до 16 символов; даём несколько разной
    длины, чтобы клиенты могли выбирать. Длина 0 (пустой) Xray тоже допускает,
    но мы её не используем — пустой shortId ослабляет различимость.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Разные длины shortId: 8 hex (4 байта) — типовая; добавляем покороче/подлиннее.
    lengths = [8, 4, 16]
    short_ids = [os.urandom(n // 2).hex() for n in lengths[:short_id_count]]

    return RealityKeys(
        private_key=_b64url_nopad(raw_priv),
        public_key=_b64url_nopad(raw_pub),
        short_ids=short_ids,
    )


def _reality_stream(network: str, keys: RealityKeys, dest: str,
                    server_names: list[str], extra: dict | None = None) -> dict:
    """streamSettings для Reality-инбаунда заданного транспорта."""
    stream = {
        "network": network,
        "security": "reality",
        "realitySettings": {
            "show": False,
            "dest": dest,
            "xver": 0,
            "serverNames": list(server_names),
            "privateKey": keys.private_key,
            "shortIds": keys.short_ids,
        },
    }
    if extra:
        stream.update(extra)
    return stream


def _tls_stream(network: str, domain: str, cert_file: str, key_file: str,
                extra: dict | None = None,
                alpn: list[str] | None = None) -> dict:
    """streamSettings для TLS-инбаунда. Сертификат — файлы acme.sh на ноде
    (HTTP-01, см. ADR 0005); пути параметризуются вызывающим кодом.

    alpn по умолчанию h2+http/1.1; ws-транспорт обязан передать только
    http/1.1 — WebSocket-апгрейд поверх h2 не работает, и клиент, отнегошиировав
    h2, не подключится."""
    stream = {
        "network": network,
        "security": "tls",
        "tlsSettings": {
            "serverName": domain,
            "alpn": list(alpn) if alpn else ["h2", "http/1.1"],
            "certificates": [
                {"certificateFile": cert_file, "keyFile": key_file},
            ],
        },
    }
    if extra:
        stream.update(extra)
    return stream


def _build_inbound(choice: InboundChoice, port: int, *, keys: RealityKeys | None,
                   dest: str, server_names: list[str], tls_domain: str | None,
                   cert_file: str | None, key_file: str | None) -> dict:
    """Собрать один inbound по выбранному пункту меню."""
    tag = choice.value

    if choice is InboundChoice.VLESS_REALITY_TCP:
        # Транспорт для reality-tcp — именно "tcp", не "raw". Хотя в свежих
        # Xray-core "raw" — новое каноничное имя (а "tcp" его алиас), панель
        # Remnawave (наша версия) проставляет клиентам flow xtls-rprx-vision,
        # только когда видит literal network:"tcp". С "raw" панель нормализует
        # подписку в type=tcp и кладёт в ссылку flow=vision, но серверным
        # клиентам инбаунда flow НЕ добавляет — получается рассинхрон: строгий
        # клиент (Happ и прочие на xray-core) шлёт Vision, сервер его не ждёт,
        # хендшейк проходит, а трафика нет («подключается, интернета нет»).
        # Проверено на живой панели: все рабочие reality-инбаунды на ней — tcp.
        return {
            "tag": tag, "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": _reality_stream("tcp", keys, dest, server_names),
        }

    if choice is InboundChoice.VLESS_XHTTP_REALITY:
        return {
            "tag": tag, "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": _reality_stream(
                "xhttp", keys, dest, server_names,
                extra={"xhttpSettings": {"path": "/"}},
            ),
        }

    if choice is InboundChoice.VLESS_GRPC_REALITY:
        return {
            "tag": tag, "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": _reality_stream(
                "grpc", keys, dest, server_names,
                extra={"grpcSettings": {"serviceName": "grpc"}},
            ),
        }

    if choice is InboundChoice.VLESS_XHTTP_TLS:
        return {
            "tag": tag, "port": port, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": _tls_stream(
                "xhttp", tls_domain, cert_file, key_file,
                extra={"xhttpSettings": {"path": "/"}},
            ),
        }

    if choice is InboundChoice.TROJAN_WS_TLS:
        return {
            "tag": tag, "port": port, "protocol": "trojan",
            "settings": {"clients": []},
            "streamSettings": _tls_stream(
                "ws", tls_domain, cert_file, key_file,
                extra={"wsSettings": {"path": "/"}},
                alpn=["http/1.1"],
            ),
        }

    if choice is InboundChoice.SHADOWSOCKS:
        # Серверный пароль SS2022 — 32 случайных байта в base64 (стандарт метода).
        server_password = base64.b64encode(os.urandom(32)).decode("ascii")
        return {
            "tag": tag, "port": port, "protocol": "shadowsocks",
            "settings": {
                "method": DEFAULT_SS_METHOD,
                "password": server_password,
                "clients": [],
                "network": "tcp,udp",
            },
            "streamSettings": {"network": "tcp"},
        }

    if choice is InboundChoice.HYSTERIA2:
        # Hysteria2 в Remnawave (нода 2.7.0+) — это inbound её форка Xray-core:
        # protocol "hysteria" + version 2, транспорт "hysteria" (QUIC поверх
        # UDP), TLS обязателен с alpn ["h3"]. Формат сверен по официальным
        # шаблонам remnawave/templates. Сертификат — тот же, что у прочих
        # доменных инбаундов (acme.sh на ноде, см. _setup_tls). Клиентов панель
        # подставляет сама, как и в остальных инбаундах.
        return {
            "tag": tag, "port": port, "listen": "0.0.0.0",
            "protocol": "hysteria",
            "settings": {"clients": [], "version": 2},
            "streamSettings": {
                "network": "hysteria",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "serverName": tls_domain,
                    "certificates": [
                        {"certificateFile": cert_file, "keyFile": key_file},
                    ],
                },
                "hysteriaSettings": {"version": 2},
            },
        }

    raise ValueError(f"неизвестный inbound: {choice!r}")


def _assign_ports(choices: list[InboundChoice],
                  overrides: dict[InboundChoice, int] | None,
                  reserved: set[int] | None = None) -> dict[InboundChoice, int]:
    """Раздать порты без конфликтов: первый → 443, дальше из FALLBACK_PORTS.

    overrides позволяет оператору закрепить порт за конкретным inbound'ом.
    reserved — порты, которые раздавать нельзя (уже заняты инбаундами
    существующего профиля при повторном провижне).
    """
    overrides = overrides or {}
    used: set[int] = set(overrides.values()) | set(reserved or ())
    ports: dict[InboundChoice, int] = {}
    pool = iter((PORT_443, *FALLBACK_PORTS))

    for choice in choices:
        if choice in overrides:
            ports[choice] = overrides[choice]
            continue
        try:
            port = next(pool)
            while port in used:
                port = next(pool)
        except StopIteration:
            raise ValueError(
                "пул портов инбаундов исчерпан: слишком много инбаундов "
                "или занятых портов в профиле"
            ) from None
        ports[choice] = port
        used.add(port)
    return ports


def build_profile(
    choices: list[InboundChoice],
    *,
    reality_dest: str = DEFAULT_REALITY_DEST,
    reality_server_names: tuple[str, ...] = DEFAULT_REALITY_SERVER_NAMES,
    tls_domain: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    port_overrides: dict[InboundChoice, int] | None = None,
    tag_suffix: str = "",
    reserved_ports: set[int] | None = None,
) -> GeneratedProfile:
    """Собрать полный Xray-конфиг под выбранные inbound'ы.

    choices — непустой список выбранных пунктов меню (ADR 0005: дефолт «все»,
    пустой выбор блокируется ещё в UI, но проверяем и здесь). Для TLS-вариантов
    обязателен tls_domain и пути к сертификату; для Reality-вариантов ключи
    генерируются автоматически — каждый Reality-inbound получает свою пару.

    tag_suffix делает теги инбаундов уникальными в пределах всей панели (она
    отвергает дубль тега с 409). Передаём сюда стабильный per-node идентификатор
    (например, slug IP) — иначе вторая нода ловит «Inbounds with same tag already
    exists», т.к. набор пунктов меню у всех нод одинаков.

    reserved_ports — порты, уже занятые существующим профилем ноды: при
    повторном провижне новые инбаунды дописываются в тот же профиль и не должны
    конфликтовать портами со старыми.
    """
    if not choices:
        raise ValueError("список inbound'ов пуст: нужен хотя бы один")

    # Уникализируем, сохраняя порядок (от него зависит, кто получит 443).
    seen: set[InboundChoice] = set()
    ordered = [c for c in choices if not (c in seen or seen.add(c))]

    needs_tls = any(c in TLS_CHOICES for c in ordered)
    if needs_tls and not (tls_domain and cert_file and key_file):
        raise ValueError(
            "для TLS-инбаундов нужны tls_domain, cert_file и key_file"
        )

    ports = _assign_ports(ordered, port_overrides, reserved_ports)

    inbounds: list[dict] = []
    tags: list[str] = []
    reality_keys: dict[str, RealityKeys] = {}
    ports_by_tag: dict[str, int] = {}
    hosts: dict[str, HostHint] = {}
    udp_ports: list[int] = []

    for choice in ordered:
        keys = generate_reality_keys() if choice in REALITY_CHOICES else None
        inbound = _build_inbound(
            choice, ports[choice],
            keys=keys,
            dest=reality_dest, server_names=list(reality_server_names),
            tls_domain=tls_domain, cert_file=cert_file, key_file=key_file,
        )
        # Тег обязан быть уникальным в пределах всей панели — добавляем per-node
        # суффикс. Базовый тег (= значению пункта меню) при этом сохраняется как
        # префикс, чтобы оставаться читаемым в UI панели.
        tag = inbound["tag"]
        if tag_suffix:
            tag = f"{tag}-{tag_suffix}"
            inbound["tag"] = tag
        inbounds.append(inbound)
        tags.append(tag)
        ports_by_tag[tag] = ports[choice]
        hosts[tag] = _host_hint(
            choice,
            server_names=list(reality_server_names),
            tls_domain=tls_domain,
        )
        # UDP-инбаунды (для UFW открыть порт по udp): Shadowsocks (tcp,udp) и
        # Hysteria2 (чистый QUIC/UDP).
        if choice in (InboundChoice.SHADOWSOCKS, InboundChoice.HYSTERIA2):
            udp_ports.append(ports[choice])
        if keys is not None:
            reality_keys[tag] = keys

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"rules": []},
    }

    return GeneratedProfile(
        config=config, tags=tags, reality_keys=reality_keys, ports=ports_by_tag,
        hosts=hosts, udp_ports=udp_ports,
    )
