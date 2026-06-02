"""Обёртка над Remnawave API (SDK remnawave 2.7.x).

Работает одинаково для своей панели и для чужой (bring-your-own-panel, ADR 0001):
URL и токен передаются в конструктор. Токен берётся из Vault, не из БД.

Важно про модель авторизации ноды в 2.7.x. CreateNode НЕ выдаёт per-node
секрет и порт контейнера — нода доверяет панели по её публичному ключу. Этот
ключ один на панель и берётся из /keygen (`get_panel_pubkey`); он кладётся в
контейнер remnanode переменной SSL_CERT. Порт ноды задаём мы сами при создании
(поле `port`), панель его не генерирует.

Статуса-строки «online» в API тоже нет: состояние ноды выводится из флагов
isConnected / isConnecting / isDisabled (см. `_derive_status`).
"""
from __future__ import annotations

import enum
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


class NodeConnState(str, enum.Enum):
    """Состояние подключения ноды, выведенное из флагов панели."""

    ONLINE = "online"          # isConnected, активна
    CONNECTING = "connecting"  # панель ещё устанавливает соединение
    DISABLED = "disabled"      # нода выключена оператором
    OFFLINE = "offline"        # не подключена и не подключается


@dataclass
class NodeInfo:
    """Срез данных ноды, нужный оркестратору."""

    uuid: str
    name: str
    address: str
    port: int | None
    status: NodeConnState


@dataclass
class ConfigProfileRef:
    """Профиль конфигурации панели и его инбаунды (нужны для CreateNode)."""

    uuid: str
    name: str
    inbound_uuids: list[str]


@dataclass
class CreatedProfile:
    """Только что созданный профиль: его uuid и карта tag→inbound_uuid.

    Теги панель присваивает инбаундам сама при разборе нашего Xray-конфига,
    поэтому связать «что мы сгенерировали» с «что зарегистрировала панель»
    можно только по тегам. Эта карта нужна, чтобы передать в create_node
    UUID'ы именно выбранных оператором инбаундов.
    """

    uuid: str
    tag_to_inbound: dict[str, str]


def _derive_status(node) -> NodeConnState:
    """Свести флаги ответа панели к одному состоянию.

    Порядок проверок важен: выключенная нода — это терминальное состояние,
    оно важнее, чем «подключается». Дальше connected → connecting → offline.
    """
    if getattr(node, "is_disabled", False):
        return NodeConnState.DISABLED
    if getattr(node, "is_connected", False):
        return NodeConnState.ONLINE
    if getattr(node, "is_connecting", False):
        return NodeConnState.CONNECTING
    return NodeConnState.OFFLINE


def _to_info(node) -> NodeInfo:
    return NodeInfo(
        uuid=str(node.uuid),
        name=node.name,
        address=node.address,
        port=node.port,
        status=_derive_status(node),
    )


def _build_create_request(
    name: str,
    address: str,
    port: int | None,
    config_profile_uuid: str,
    active_inbounds: list[str],
    country_code: str,
):
    """Собрать CreateNodeRequestDto. Импорт ленивый, чтобы клиент можно было
    конструировать с подменённым sdk без установленного пакета remnawave."""
    from uuid import UUID

    from remnawave.models import CreateNodeRequestDto, NodeConfigProfileRequestDto

    return CreateNodeRequestDto(
        name=name,
        address=address,
        port=port,
        country_code=country_code,
        config_profile=NodeConfigProfileRequestDto(
            activeConfigProfileUuid=UUID(str(config_profile_uuid)),
            activeInbounds=[UUID(str(i)) for i in active_inbounds],
        ),
    )


def _build_config_profile_request(name: str, config: dict):
    """Собрать CreateConfigProfileRequestDto. Импорт ленивый — как и в
    _build_create_request, чтобы тесты работали без пакета remnawave."""
    from remnawave.models import CreateConfigProfileRequestDto

    return CreateConfigProfileRequestDto(name=name, config=config)


class RemnawaveClient:
    """Тонкая обёртка над RemnawaveSDK с доменными типами оркестратора.

    sdk можно передать готовым (для тестов/инъекции). По умолчанию строится из
    panel_url + api_token.
    """

    def __init__(
        self,
        panel_url: str,
        api_token: str,
        *,
        ssl_ignore: bool = False,
        sdk=None,
    ) -> None:
        self.panel_url = panel_url.rstrip("/")
        self._token = api_token
        if sdk is None:
            from remnawave import RemnawaveSDK

            sdk = RemnawaveSDK(
                base_url=self.panel_url,
                token=api_token,
                ssl_ignore=ssl_ignore,
            )
        self._sdk = sdk

    async def get_panel_pubkey(self) -> str:
        """Публичный ключ панели → SSL_CERT для контейнера remnanode."""
        resp = await self._sdk.keygen.generate_key()
        return resp.pub_key

    async def list_config_profiles(self) -> list[ConfigProfileRef]:
        """Профили конфигурации панели с их инбаундами.

        Для MVP (single-tenant, одна типовая раскладка) обычно берут первый
        профиль и все его инбаунды — этим займётся вызывающий код в tasks.py.
        """
        resp = await self._sdk.config_profiles.get_config_profiles()
        return [
            ConfigProfileRef(
                uuid=str(p.uuid),
                name=p.name,
                inbound_uuids=[str(inb.uuid) for inb in p.inbounds],
            )
            for p in resp.config_profiles
        ]

    async def create_config_profile(self, name: str, config: dict) -> CreatedProfile:
        """Создать config-profile из готового Xray-конфига (вариант «авто»).

        config — это полный Xray-JSON, собранный xray_config.build_profile().
        Панель сама разбирает inbounds и присваивает им uuid'ы и теги; возвращаем
        uuid профиля и карту tag→inbound_uuid, по которой вызывающий код выбирает
        нужные инбаунды для create_node.
        """
        body = _build_config_profile_request(name, config)
        resp = await self._sdk.config_profiles.create_config_profile(body=body)
        return CreatedProfile(
            uuid=str(resp.uuid),
            tag_to_inbound={inb.tag: str(inb.uuid) for inb in resp.inbounds},
        )

    async def create_node(
        self,
        name: str,
        address: str,
        config_profile_uuid: str,
        active_inbounds: list[str],
        *,
        port: int | None = None,
        country_code: str = "XX",
    ) -> NodeInfo:
        """Зарегистрировать ноду в панели.

        config_profile_uuid + active_inbounds обязательны для 2.7.x: панель
        привязывает ноду к профилю и набору инбаундов сразу при создании.
        Секрет/порт контейнера тут не возвращаются — авторизация по pubKey
        панели (см. модуль docstring и get_panel_pubkey).
        """
        body = _build_create_request(
            name, address, port, config_profile_uuid, active_inbounds, country_code
        )
        node = await self._sdk.nodes.create_node(body=body)
        return _to_info(node)

    async def get_node_status(self, uuid: str) -> NodeConnState:
        """Состояние ноды по uuid; поллим до NodeConnState.ONLINE."""
        node = await self._sdk.nodes.get_one_node(uuid=str(uuid))
        return _derive_status(node)
