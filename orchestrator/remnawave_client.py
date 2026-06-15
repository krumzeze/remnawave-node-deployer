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


@dataclass
class InternalSquadRef:
    """Внутренний сквад панели и uuid'ы его инбаундов.

    Сквад — это группа доступа: пользователь видит инбаунд (а значит и ноду с
    хостом на этот инбаунд), только если инбаунд входит в его сквад. inbound_uuids
    нужны для read-modify-write при добавлении новых инбаундов (см. ADR 0008).
    """

    uuid: str
    name: str
    inbound_uuids: list[str]


@dataclass
class CreatedHost:
    """Только что созданный хост — точка входа, которую видит пользователь."""

    uuid: str
    remark: str
    address: str
    port: int


@dataclass
class HostRef:
    """Срез существующего хоста панели для дедупликации при повторном провижене.

    inbound_uuid может быть недоступен в ответе SDK (форма не зафиксирована),
    поэтому он опционален; надёжный минимум для сравнения — address + port.
    """

    uuid: str
    remark: str
    address: str
    port: int | None
    inbound_uuid: str | None


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


def _host_inbound_uuid(host) -> str | None:
    """Достать uuid инбаунда из элемента листинга хостов.

    Форма ответа SDK не зафиксирована: uuid инбаунда встречается то прямо в
    host'е (inbound_uuid/config_profile_inbound_uuid), то во вложенном объекте
    inbound. Пробуем по очереди, при отсутствии — None (тогда сверка идёт только
    по address+port)."""
    for attr in ("inbound_uuid", "config_profile_inbound_uuid"):
        val = getattr(host, attr, None)
        if val:
            return str(val)
    inbound = getattr(host, "inbound", None)
    if inbound is not None:
        for attr in ("config_profile_inbound_uuid", "uuid"):
            val = getattr(inbound, attr, None)
            if val:
                return str(val)
    return None


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


def _build_create_host_request(
    *,
    inbound_uuid: str,
    config_profile_uuid: str,
    remark: str,
    address: str,
    port: int,
    node_uuid: str | None,
    security: str,
    sni: str | None,
    host: str | None,
    path: str | None,
    fingerprint: str | None,
    alpn: str | None,
):
    """Собрать CreateHostRequestDto. Импорт ленивый — как и у остальных билдеров.

    security — доменная строка («reality»/«tls»/«none»/«default»); мапим её на
    SecurityLayer панели, чтобы выше по стеку не тянуть энумы SDK. У панели
    securityLayer всего три значения: DEFAULT, TLS, NONE. Reality отдельного
    значения не имеет — он настраивается на инбаунде, а хост наследует его
    через DEFAULT, поэтому «reality» мапим на DEFAULT. Хост ссылается на
    инбаунд профиля (config_profile_uuid + inbound_uuid); nodes — это лишь
    визуальная привязка к ноде в UI панели, на доступ она не влияет.
    """
    from uuid import UUID

    from remnawave.enums import ALPN, Fingerprint, SecurityLayer
    from remnawave.models import CreateHostInboundData, CreateHostRequestDto

    sec_map = {
        "reality": SecurityLayer.DEFAULT,
        "tls": SecurityLayer.TLS,
        "none": SecurityLayer.NONE,
        "default": SecurityLayer.DEFAULT,
    }
    kwargs: dict = {
        "inbound": CreateHostInboundData(
            config_profile_uuid=UUID(str(config_profile_uuid)),
            config_profile_inbound_uuid=UUID(str(inbound_uuid)),
        ),
        "remark": remark,
        "address": address,
        "port": port,
        "security_layer": sec_map.get(security, SecurityLayer.DEFAULT),
    }
    if sni:
        kwargs["sni"] = sni
    if host:
        kwargs["host"] = host
    if path:
        kwargs["path"] = path
    if fingerprint:
        kwargs["fingerprint"] = Fingerprint(fingerprint)
    if alpn:
        kwargs["alpn"] = ALPN(alpn)
    if node_uuid:
        kwargs["nodes"] = [UUID(str(node_uuid))]
    return CreateHostRequestDto(**kwargs)


def _build_update_squad_request(uuid: str, inbound_uuids: list[str]):
    """Собрать UpdateInternalSquadRequestDto. name не передаём — он остаётся как
    был; передаём только полный (объединённый) список инбаундов, т.к. update на
    стороне панели заменяет его целиком."""
    from uuid import UUID

    from remnawave.models import UpdateInternalSquadRequestDto

    return UpdateInternalSquadRequestDto(
        uuid=UUID(str(uuid)),
        inbounds=[UUID(str(i)) for i in inbound_uuids],
    )


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

    async def _find_config_profile(self, name: str) -> CreatedProfile | None:
        """Найти профиль по имени и собрать карту tag→inbound_uuid, либо None.

        Нужно для идемпотентности create_config_profile: повторный провижн той же
        ноды не должен плодить дубли профилей в панели. Защитно: если листинг не
        получился или у inbound'ов нет тегов — возвращаем None и создаём заново.
        """
        try:
            resp = await self._sdk.config_profiles.get_config_profiles()
        except Exception:  # noqa: BLE001 — недоступность листинга не должна ломать создание
            return None
        for prof in getattr(resp, "config_profiles", None) or []:
            if getattr(prof, "name", None) != name:
                continue
            mapping = {
                inb.tag: str(inb.uuid)
                for inb in (getattr(prof, "inbounds", None) or [])
                if getattr(inb, "tag", None) is not None
            }
            if not mapping:
                return None
            return CreatedProfile(uuid=str(prof.uuid), tag_to_inbound=mapping)
        return None

    async def create_config_profile(self, name: str, config: dict) -> CreatedProfile:
        """Создать config-profile из готового Xray-конфига (вариант «авто»).

        config — это полный Xray-JSON, собранный xray_config.build_profile().
        Панель сама разбирает inbounds и присваивает им uuid'ы и теги; возвращаем
        uuid профиля и карту tag→inbound_uuid, по которой вызывающий код выбирает
        нужные инбаунды для create_node.

        Идемпотентно: если профиль с таким именем уже есть (повторный запуск той
        же ноды), переиспользуем его, а не создаём дубль.
        """
        existing = await self._find_config_profile(name)
        if existing is not None:
            log.info("config-profile %s уже есть — переиспользую", name)
            return existing
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

        Идемпотентно: если нода с таким адресом уже зарегистрирована (повторный
        запуск), переиспользуем её, а не заводим дубль.
        """
        existing = await self._find_node_by_address(address)
        if existing is not None:
            log.info("нода с адресом %s уже есть — переиспользую", address)
            return existing
        body = _build_create_request(
            name, address, port, config_profile_uuid, active_inbounds, country_code
        )
        node = await self._sdk.nodes.create_node(body=body)
        return _to_info(node)

    async def list_nodes(self) -> list[NodeInfo]:
        """Все ноды панели как доменные NodeInfo.

        Нужно для синка существующих нод в бота (кнопка «Синхронизировать») и для
        идемпотентности create_node (см. _find_node_by_address). Защитно, как и
        list_hosts: нет метода листинга у SDK или вызов упал/отдал неожиданную
        форму — возвращаем пустой список вместо падения. Форма ответа SDK 2.7.x —
        объект с `.nodes`, либо голый список."""
        getter = getattr(self._sdk.nodes, "get_all_nodes", None)
        if getter is None:
            return []
        try:
            resp = await getter()
        except Exception:  # noqa: BLE001 — недоступность листинга не ломает вызывающий код
            return []
        nodes = getattr(resp, "nodes", None)
        if nodes is None:
            nodes = resp if isinstance(resp, list) else []
        return [_to_info(n) for n in nodes]

    async def _find_node_by_address(self, address: str) -> NodeInfo | None:
        """Найти зарегистрированную ноду по адресу, либо None.

        Нужно для идемпотентности create_node. Листинг защитный (см. list_nodes):
        недоступен — вернётся [], и create_node пойдёт обычным путём создания
        (хуже дубль, чем падение всего провижина)."""
        for node in await self.list_nodes():
            if node.address == address:
                return node
        return None

    async def get_node_status(self, uuid: str) -> NodeConnState:
        """Состояние ноды по uuid; поллим до NodeConnState.ONLINE."""
        node = await self._sdk.nodes.get_one_node(uuid=str(uuid))
        return _derive_status(node)

    async def list_hosts(self) -> list[HostRef]:
        """Существующие хосты панели для дедупликации при повторном провижене.

        Нужно, чтобы повторный запуск той же ноды не плодил дубли хостов: перед
        созданием хоста вызывающий код сверяется с этим списком. Защитно, как и
        _find_node_by_address: нет метода у SDK или вызов упал/отдал неожиданную
        форму — возвращаем пустой список, и публикация идёт обычным путём
        (создаём всё; хуже дубль, чем падение всего провижина).

        Форма ответа SDK 2.7.x не зафиксирована, поэтому поля и привязку к
        инбаунду тянем через getattr с фолбэками; uuid инбаунда у разных версий
        лежит то в самом host'е, то во вложенном объекте inbound."""
        getter = getattr(self._sdk.hosts, "get_all_hosts", None)
        if getter is None:
            return []
        try:
            resp = await getter()
        except Exception:  # noqa: BLE001 — недоступность листинга не ломает публикацию
            return []
        items = getattr(resp, "hosts", None)
        if items is None:
            items = resp if isinstance(resp, list) else []
        return [
            HostRef(
                uuid=str(getattr(h, "uuid", "")),
                remark=getattr(h, "remark", "") or "",
                address=getattr(h, "address", "") or "",
                port=getattr(h, "port", None),
                inbound_uuid=_host_inbound_uuid(h),
            )
            for h in items
        ]

    async def create_host(
        self,
        *,
        inbound_uuid: str,
        config_profile_uuid: str,
        remark: str,
        address: str,
        port: int,
        node_uuid: str | None = None,
        security: str = "default",
        sni: str | None = None,
        host: str | None = None,
        path: str | None = None,
        fingerprint: str | None = None,
        alpn: str | None = None,
    ) -> CreatedHost:
        """Создать хост — строку подключения, которую панель отдаёт в подписке.

        Один хост на один инбаунд ноды. Параметры (security/sni/path/...) приходят
        из генератора Xray-конфига, оператор их не вводит (ADR 0008).
        """
        body = _build_create_host_request(
            inbound_uuid=inbound_uuid,
            config_profile_uuid=config_profile_uuid,
            remark=remark,
            address=address,
            port=port,
            node_uuid=node_uuid,
            security=security,
            sni=sni,
            host=host,
            path=path,
            fingerprint=fingerprint,
            alpn=alpn,
        )
        resp = await self._sdk.hosts.create_host(body=body)
        return CreatedHost(
            uuid=str(resp.uuid),
            remark=resp.remark,
            address=resp.address,
            port=resp.port,
        )

    async def list_internal_squads(self) -> list[InternalSquadRef]:
        """Внутренние сквады панели с их инбаундами (для выбора в боте и для
        read-modify-write при привязке)."""
        resp = await self._sdk.internal_squads.get_internal_squads()
        return [
            InternalSquadRef(
                uuid=str(s.uuid),
                name=s.name,
                inbound_uuids=[str(inb.uuid) for inb in s.inbounds],
            )
            for s in resp.internal_squads
        ]

    async def add_inbounds_to_squads(
        self, squad_uuids: list[str], new_inbound_uuids: list[str]
    ) -> None:
        """Дописать инбаунды в указанные сквады (read-modify-write).

        update_internal_squad заменяет список инбаундов целиком, поэтому сначала
        читаем текущий состав каждого сквада, объединяем со своими (без дублей,
        порядок сохраняем) и отправляем обратно. Сквады панели читаем один раз.
        """
        if not squad_uuids or not new_inbound_uuids:
            return
        by_uuid = {s.uuid: s for s in await self.list_internal_squads()}
        add = [str(u) for u in new_inbound_uuids]
        for su in squad_uuids:
            squad = by_uuid.get(str(su))
            if squad is None:
                raise ValueError(f"внутренний сквад {su} не найден в панели")
            merged = list(dict.fromkeys(squad.inbound_uuids + add))
            body = _build_update_squad_request(squad.uuid, merged)
            await self._sdk.internal_squads.update_internal_squad(body=body)
