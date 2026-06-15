"""Сборка routing-профиля Happ для обхода российских сервисов.

Задача (см. research/ru-bypass-happ-routing): по умолчанию весь трафик идёт в
туннель (маскировка Reality), но на российские сервисы клиент ходит напрямую —
чтобы сервис видел реальный домашний IP пользователя, а не иностранный IP ноды.
Разделение трафика — клиентское (его делает приложение Happ), а не серверное:
нода заграничная, поэтому direct-выход с самой ноды цель бы не закрыл.

Профиль доставляется панелью: строка-deeplink кладётся в настройку подписки
`happRouting` (см. RemnawaveClient.set_happ_routing), панель прикладывает её к
ответу подписки, и Happ подхватывает профиль при ближайшем обновлении. Это
панель-уровень, ноды и xray_config тут ни при чём.

Формат профиля — JSON Happ (поля Name/GlobalProxy/DirectSites/DirectIp/DNS...),
deeplink — `happ://routing/<mode>/<base64(json)>`. Режим `onadd` применяет
профиль автоматически, без действий пользователя.
"""
from __future__ import annotations

import base64
import json

# Routing-профиль «обход РФ». GlobalProxy=true — по умолчанию всё в туннель;
# Direct* — исключения, которые идут мимо туннеля напрямую. Охват РФ задан
# гео-категориями (geosite/geoip из встроенных баз Happ), приватные сети — чтобы
# локалка и RFC1918 не заворачивались в туннель. DNS делится сам: Remote DNS
# (Cloudflare DoH) для проксируемых ресурсов, Domestic DNS (Яндекс) для
# direct-ресурсов — отдельной защиты от DNS-утечек не требуется.
#
# Охват РФ-сайтов. Главное — не зависеть от geosite-базы Happ (Loyalsoldier):
# кода geosite:ru/geosite:geolocation-ru там нет, и Xray грузит .dat при старте,
# нормализуя код в верхний регистр, — на отсутствующем коде ядро падает с
# «code not found in geosite.dat: RU», и Happ вообще не стартует. А имеющийся
# geosite:category-ru — около 230 доменов на всю Россию, мимо него уходила
# основная масса РФ-трафика.
#
# Поэтому ядро покрытия — правила domain:, которые в geosite.dat не лезут вообще
# (буквальное совпадение по суффиксу): domain:ru/xn--p1ai/su накрывают весь
# российский TLD одним махом и не могут уронить ядро. geoip:ru в DirectIp при
# DomainStrategy=IPIfNonMatch добивает российские сервисы на .com (домен
# резолвится, IP оказывается российским → direct). geosite:category-ru и явный
# domain:vk.com — добивка поверх (category-ru у клиента грузится, краша на нём
# не было).
RU_BYPASS_PROFILE: dict = {
    "Name": "RU bypass",
    "GlobalProxy": "true",
    "RemoteDNSType": "DoH",
    "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
    "RemoteDNSIP": "1.1.1.1",
    "DomesticDNSType": "DoU",
    "DomesticDNSIP": "77.88.8.8",
    "DirectSites": [
        "domain:ru",
        "domain:xn--p1ai",
        "domain:su",
        "domain:vk.com",
        "geosite:category-ru",
    ],
    "DirectIp": ["geoip:ru", "geoip:private"],
    "ProxySites": [],
    "ProxyIp": [],
    "BlockSites": [],
    "BlockIp": [],
    "DomainStrategy": "IPIfNonMatch",
    "FakeDNS": "false",
}


def build_deeplink(profile: dict, *, mode: str = "onadd") -> str:
    """Собрать deeplink Happ из routing-профиля.

    profile сериализуется в компактный JSON и кодируется стандартным base64
    (как ждут deeplink'и Happ). mode — `onadd` (применить автоматически) или
    `add` (пользователь подтверждает применение в Happ).
    """
    raw = json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return f"happ://routing/{mode}/{encoded}"


def build_ru_bypass_deeplink() -> str:
    """Deeplink профиля «обход РФ» с автоприменением (onadd)."""
    return build_deeplink(RU_BYPASS_PROFILE, mode="onadd")
