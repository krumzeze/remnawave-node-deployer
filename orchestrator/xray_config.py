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


class InboundChoice(str, enum.Enum):
    """Пункты меню inbound'ов из ADR 0005."""

    VLESS_REALITY_TCP = "vless-reality-tcp"      # domain-free
    VLESS_XHTTP_REALITY = "vless-xhttp-reality"  # domain-free
    VLESS_XHTTP_TLS = "vless-xhttp-tls"          # нужен домен
    VLESS_GRPC_REALITY = "vless-grpc-reality"    # domain-free
    TROJAN_WS_TLS = "trojan-ws-tls"              # нужен домен
    SHADOWSOCKS = "shadowsocks"                  # domain-free


# Какие варианты требуют домена и сертификата (ветка TLS в ADR 0005).
TLS_CHOICES = frozenset({InboundChoice.VLESS_XHTTP_TLS, InboundChoice.TROJAN_WS_TLS})

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
FALLBACK_PORTS = (8443, 2053, 2083, 2087, 2096)


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
                extra: dict | None = None) -> dict:
    """streamSettings для TLS-инбаунда. Сертификат — файлы acme.sh на ноде
    (HTTP-01, см. ADR 0005); пути параметризуются вызывающим кодом."""
    stream = {
        "network": network,
        "security": "tls",
        "tlsSettings": {
            "serverName": domain,
            "alpn": ["h2", "http/1.1"],
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

    raise ValueError(f"неизвестный inbound: {choice!r}")


def _assign_ports(choices: list[InboundChoice],
                  overrides: dict[InboundChoice, int] | None) -> dict[InboundChoice, int]:
    """Раздать порты без конфликтов: первый → 443, дальше из FALLBACK_PORTS.

    overrides позволяет оператору закрепить порт за конкретным inbound'ом.
    """
    overrides = overrides or {}
    used: set[int] = set(overrides.values())
    ports: dict[InboundChoice, int] = {}
    pool = iter((PORT_443, *FALLBACK_PORTS))

    for choice in choices:
        if choice in overrides:
            ports[choice] = overrides[choice]
            continue
        port = next(pool)
        while port in used:
            port = next(pool)
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
) -> GeneratedProfile:
    """Собрать полный Xray-конфиг под выбранные inbound'ы.

    choices — непустой список выбранных пунктов меню (ADR 0005: дефолт «все»,
    пустой выбор блокируется ещё в UI, но проверяем и здесь). Для TLS-вариантов
    обязателен tls_domain и пути к сертификату; для Reality-вариантов ключи
    генерируются автоматически — каждый Reality-inbound получает свою пару.
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

    ports = _assign_ports(ordered, port_overrides)

    inbounds: list[dict] = []
    tags: list[str] = []
    reality_keys: dict[str, RealityKeys] = {}
    ports_by_tag: dict[str, int] = {}

    for choice in ordered:
        keys = generate_reality_keys() if choice in REALITY_CHOICES else None
        inbound = _build_inbound(
            choice, ports[choice],
            keys=keys,
            dest=reality_dest, server_names=list(reality_server_names),
            tls_domain=tls_domain, cert_file=cert_file, key_file=key_file,
        )
        inbounds.append(inbound)
        tags.append(inbound["tag"])
        ports_by_tag[inbound["tag"]] = ports[choice]
        if keys is not None:
            reality_keys[inbound["tag"]] = keys

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
        config=config, tags=tags, reality_keys=reality_keys, ports=ports_by_tag
    )
