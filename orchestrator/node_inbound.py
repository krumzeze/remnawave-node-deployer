"""Добавление одного инбаунда к уже развёрнутой ноде (Фаза 3 Hysteria2).

Оператор из карточки ноды выбирает инбаунд, совместимый с тем, что на ноде уже
есть (см. xray_config.available_choices_for_node), и мы добавляем его, не трогая
остальные. В отличие от полного провижина здесь НЕ выпускаем сертификат и не
разворачиваем контейнер: доменные инбаунды предлагаются только когда домен с
сертификатом на ноде уже есть, а сам сертификат (домен и пути) переиспользуем из
существующего TLS-инбаунда профиля.

Порядок (read-modify-write поверх панели + один SSH на открытие порта):
1. читаем активный профиль ноды и её включённые инбаунды (get_node_config);
2. читаем полный config профиля (get_config_profile) — все inbounds;
3. генерируем новый inbound на свободном порту (build_profile с одним пунктом);
4. дописываем его в config и шлём update_config_profile — панель отдаёт uuid;
5. включаем новый inbound в активные у ноды (update_node_active_inbounds);
6. открываем его порт в UFW по SSH (tcp/udp);
7. заводим host и добавляем inbound в выбранные сквады (как при провижине).

Как и tasks.py/monitor.py, собрано на инъектируемых швах (клиент панели, открытие
порта, доступ к Vault), чтобы проверяться без живой панели, ноды и SSH.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

from orchestrator import xray_config
from orchestrator.xray_config import (
    PORT_443,
    FALLBACK_PORTS,
    InboundChoice,
    REALITY_CHOICES,
    TLS_CHOICES,
)

logger = logging.getLogger(__name__)


@dataclass
class AddInboundResult:
    ok: bool
    detail: str


def _free_port(used: set[int]) -> int | None:
    """Первый свободный порт из того же пула, что и при провижине (443 → фолбэки)."""
    for p in (PORT_443, *FALLBACK_PORTS):
        if p not in used:
            return p
    return None


def _extract_reality_donor(config: dict) -> tuple[str, tuple[str, ...]] | None:
    """Достать (dest, serverNames) из первого Reality-инбаунда профиля.

    Донор Reality — per-node (ADR 0007): если нода разворачивалась с кастомным
    донором, добавляемый Reality-инбаунд должен использовать его же, а не дефолт
    генератора. Нет Reality-инбаундов — None (возьмётся дефолт)."""
    for inb in config.get("inbounds", []) or []:
        ss = inb.get("streamSettings") or {}
        if ss.get("security") != "reality":
            continue
        rs = ss.get("realitySettings") or {}
        dest = rs.get("dest") or rs.get("target")
        names = rs.get("serverNames") or []
        if dest and names:
            return dest, tuple(names)
    return None


def _extract_tls(config: dict) -> tuple[str, str, str] | None:
    """Достать (домен, cert_file, key_file) из первого TLS-инбаунда профиля.

    Доменный инбаунд (TLS/Hysteria2) добавляем только к ноде, где такой уже есть,
    поэтому переиспользуем уже выпущенный сертификат: его домен и пути лежат прямо
    в streamSettings существующего инбаунда. Если ни одного TLS-инбаунда нет —
    None (значит домена на ноде нет, доменный инбаунд добавить нельзя)."""
    for inb in config.get("inbounds", []) or []:
        ss = inb.get("streamSettings") or {}
        if ss.get("security") != "tls":
            continue
        tls = ss.get("tlsSettings") or {}
        domain = tls.get("serverName")
        certs = tls.get("certificates") or []
        if domain and certs:
            cert_file = certs[0].get("certificateFile")
            key_file = certs[0].get("keyFile")
            if cert_file and key_file:
                return domain, cert_file, key_file
    return None


async def add_inbound_to_node(
    *,
    choice: InboundChoice,
    ip: str,
    node_uuid: str,
    country_code: str,
    ssh_login: str,
    ssh_private_key: str,
    client,
    open_port: Callable[..., Awaitable],
    squad_uuids: list[str] | None = None,
) -> AddInboundResult:
    """Добавить инбаунд `choice` к ноде. Возвращает AddInboundResult.

    client — RemnawaveClient (или совместимый фейк). open_port — шов
    node_ops.open_port. Любой шаг, который не удался, возвращает ok=False с
    понятным текстом; необратимое (update профиля) идёт после всех проверок."""
    # 1-2. Профиль ноды и его полный config.
    node_cfg = await client.get_node_config(node_uuid)
    if not node_cfg.profile_uuid:
        return AddInboundResult(False, "У ноды не определён профиль конфигурации.")
    profile = await client.get_config_profile(node_cfg.profile_uuid)
    config = profile.config

    used = xray_config.used_ports(config)
    new_port = _free_port(used)
    if new_port is None:
        return AddInboundResult(False, "Нет свободного порта для нового инбаунда.")

    # Домен/сертификат для доменного инбаунда — из существующего TLS-инбаунда.
    tls_domain = cert_file = key_file = None
    if choice in TLS_CHOICES:
        tls = _extract_tls(config)
        if tls is None:
            return AddInboundResult(
                False, "На ноде нет домена с сертификатом — доменный инбаунд "
                "добавить нельзя.",
            )
        tls_domain, cert_file, key_file = tls

    # Донор Reality — тот же, что у существующих Reality-инбаундов ноды (если
    # они есть): нода могла разворачиваться с кастомным донором (ADR 0007).
    donor_kwargs: dict = {}
    if choice in REALITY_CHOICES:
        donor = _extract_reality_donor(config)
        if donor is not None:
            donor_kwargs = {
                "reality_dest": donor[0],
                "reality_server_names": donor[1],
            }

    # 3. Генерируем один inbound на свободном порту, тегами per-node (как провижн).
    tag_suffix = ip.replace(".", "-")
    generated = xray_config.build_profile(
        [choice],
        tls_domain=tls_domain, cert_file=cert_file, key_file=key_file,
        port_overrides={choice: new_port},
        tag_suffix=tag_suffix,
        **donor_kwargs,
    )
    new_tag = generated.tags[0]
    new_inbound = generated.config["inbounds"][0]
    is_udp = new_port in generated.udp_ports
    hint = generated.hosts.get(new_tag)

    # 4. Дописываем inbound в config профиля и обновляем профиль.
    config.setdefault("inbounds", []).append(new_inbound)
    updated = await client.update_config_profile(node_cfg.profile_uuid, config)
    new_inbound_uuid = updated.tag_to_inbound.get(new_tag)
    if not new_inbound_uuid:
        return AddInboundResult(
            False, "Панель не вернула uuid нового инбаунда после обновления профиля.",
        )

    # 5. Включаем новый inbound в активные у ноды (к старым добавляем новый).
    active = list(dict.fromkeys(node_cfg.active_inbound_uuids + [new_inbound_uuid]))
    await client.update_node_active_inbounds(node_uuid, node_cfg.profile_uuid, active)

    # 6. Открываем порт инбаунда по SSH (tcp/udp).
    port_res = await open_port(
        ip, ssh_login, ssh_private_key, new_port, udp=is_udp
    )
    if not getattr(port_res, "ok", False):
        # Профиль/нода уже обновлены, но порт не открыт — инбаунд не примет трафик.
        # Сообщаем прямо, чтобы оператор открыл порт вручную/повторил.
        return AddInboundResult(
            False, f"Инбаунд заведён, но порт открыть не вышло: "
            f"{getattr(port_res, 'detail', '')}",
        )

    # 7. Host для подписки + добавление инбаунда в сквады (дефолт — все).
    security = hint.security if hint else "none"
    address = tls_domain if (security == "tls" and tls_domain) else ip
    await client.create_host(
        inbound_uuid=new_inbound_uuid,
        config_profile_uuid=node_cfg.profile_uuid,
        remark=xray_config_host_remark(country_code, hint),
        address=address,
        port=new_port,
        node_uuid=node_uuid,
        security=security,
        sni=hint.sni if hint else None,
        path=hint.path if hint else None,
        fingerprint=hint.fingerprint if hint else None,
    )

    squads = squad_uuids
    if squads is None:
        squads = [s.uuid for s in await client.list_internal_squads()]
    if squads:
        await client.add_inbounds_to_squads(squads, [new_inbound_uuid])

    return AddInboundResult(True, f"Инбаунд добавлен на порт {new_port}.")


def xray_config_host_remark(country_code: str, hint) -> str:
    """Remark host'а — переиспользуем формат из tasks (флаг страны · отпечаток).

    Импорт ленивый, чтобы не тянуть tasks (и его тяжёлые зависимости) на уровень
    модуля; фолбэк-формат на случай, если сигнатура поменяется."""
    try:
        from orchestrator.tasks import _host_remark

        return _host_remark(
            country_code,
            hint.fingerprint if hint else None,
            network=hint.network if hint else None,
        )
    except Exception:  # noqa: BLE001 — remark не критичен, не должен валить добавление
        return (country_code or "XX").upper()
