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
# Direct* — исключения, которые идут мимо туннеля напрямую. Приватные сети
# (geosite/geoip:private) — чтобы локалка и RFC1918 не заворачивались в туннель.
# DNS делится сам: Remote DNS (Cloudflare DoH) для проксируемых ресурсов,
# Domestic DNS (Яндекс) для direct-ресурсов.
#
# Охват РФ держится на ДВУХ вещах вместе — и без них bypass не работает:
#  1) своя geo-база (Geositeurl/Geoipurl). Дефолтная база Happ (Loyalsoldier)
#     для РФ почти пустая: geosite:ru там нет вовсе (ядро Xray падает на старте
#     с «code not found in geosite.dat: RU»), а geosite:category-ru — ~230
#     доменов на всю страну. Поэтому подключаем базу roscomvpn, собранную именно
#     под «РФ напрямую» (category-ru, category-geoblock-ru, whitelist).
#  2) только geosite:/geoip:-токены в Direct-списках. Happ-роутер не понимает
#     правила вида domain:ru — их он молча игнорирует (проверено: yandex.ru с
#     domain:ru всё равно уходил в туннель). Совпадение домена работает лишь
#     через geosite-категорию из базы.
# DomainStrategy=IPIfNonMatch: домен без доменного совпадения резолвится и
# матчится по IP (geoip), это добивает РФ-сервисы на чужих TLD.
#
# База — внешний сторонний репозиторий (как и Loyalsoldier у самого Happ).
# URL стабильный (jsDelivr отдаёт последний релиз с ветки release). Если нужна
# независимость — базу можно зеркалировать у себя и поменять URL ниже.
_ROSCOMVPN_GEOSITE = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite/release/geosite.dat"
_ROSCOMVPN_GEOIP = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip/release/geoip.dat"

RU_BYPASS_PROFILE: dict = {
    "Name": "RU bypass",
    "GlobalProxy": "true",
    "RemoteDNSType": "DoH",
    "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
    "RemoteDNSIP": "1.1.1.1",
    "DomesticDNSType": "DoU",
    "DomesticDNSIP": "77.88.8.8",
    "Geoipurl": _ROSCOMVPN_GEOIP,
    "Geositeurl": _ROSCOMVPN_GEOSITE,
    "DirectSites": [
        "geosite:private",
        "geosite:category-ru",
        "geosite:category-geoblock-ru",
        "geosite:whitelist",
    ],
    "DirectIp": ["geoip:private", "geoip:direct"],
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
