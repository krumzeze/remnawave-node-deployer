"""SSH-действия над уже развёрнутой нодой (ADR 0013).

Перезапуск контейнера remnanode (лёгкая первая попытка) и перезагрузка сервера
(для забитой памяти — контейнер вернётся сам: restart: always + docker в
автозапуске). Подключаемся по приватному ключу ноды из Vault. Доступно только
нодам, у которых ключ есть (свои и удочерённые); импортированными без ключа
управлять нельзя.

Если подключиться не удалось, отдаём это отдельным понятным сообщением —
обычно это значит, что сервер действительно лёг и достучаться по SSH не выходит.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import asyncssh

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 15
# Имя контейнера ноды задаётся в compose-шаблоне (container_name: remnanode),
# поэтому restart адресуется по нему, а не по сгенерированному имени compose.
NODE_CONTAINER = "remnanode"
# reboot рвёт SSH-сессию. Запускаем его в фоне с маленькой задержкой, чтобы
# сама команда успела вернуть код 0 и сессия закрылась штатно, а перезагрузка
# началась уже после нашего отключения.
_REBOOT_CMD = "nohup sh -c 'sleep 1; reboot' >/dev/null 2>&1 &"
_OUT_MAX = 300


@dataclass
class OpResult:
    ok: bool
    detail: str


async def _connect_run(
    ip: str, login: str, private_key: str, command: str, *, port: int = 22,
    out_max: int = _OUT_MAX,
) -> OpResult:
    """Подключиться по ключу и выполнить команду.

    Сбой именно подключения отделяем от сбоя команды: первое почти всегда
    значит «сервер недоступен» (лёг по памяти/сети), и сообщение об этом для
    оператора важнее, чем текст исключения."""
    try:
        conn = await asyncssh.connect(
            ip,
            port=port,
            username=login,
            client_keys=[asyncssh.import_private_key(private_key)],
            known_hosts=None,
            connect_timeout=CONNECT_TIMEOUT,
        )
    except (OSError, asyncssh.Error) as exc:
        logger.warning("node_ops: не подключиться к %s: %s", ip, exc)
        return OpResult(
            ok=False,
            detail="Сервер скорее всего недоступен — достучаться по SSH не вышло.",
        )
    try:
        res = await conn.run(command, check=False)
    except (OSError, asyncssh.Error) as exc:
        return OpResult(ok=False, detail=f"Команда не выполнилась: {exc}")
    finally:
        conn.close()

    if res.exit_status != 0:
        detail = (res.stderr or "").strip()[:out_max]
        return OpResult(ok=False, detail=detail or f"команда вернула код {res.exit_status}")
    return OpResult(ok=True, detail=(res.stdout or "").strip()[:out_max])


async def restart_node(
    ip: str, login: str, private_key: str, *, port: int = 22
) -> OpResult:
    """Перезапустить контейнер remnanode — лёгкая первая попытка лечения."""
    res = await _connect_run(
        ip, login, private_key, f"docker restart {NODE_CONTAINER}", port=port
    )
    if res.ok:
        return OpResult(ok=True, detail="Контейнер ноды перезапущен.")
    return res


async def reboot_server(
    ip: str, login: str, private_key: str, *, port: int = 22
) -> OpResult:
    """Перезагрузить сервер целиком — когда забита память и рестарт не спасает."""
    res = await _connect_run(ip, login, private_key, _REBOOT_CMD, port=port)
    if res.ok:
        return OpResult(
            ok=True,
            detail="Команда на перезагрузку отправлена. Нода вернётся сама "
            "через пару минут (статус обновит поллер).",
        )
    return res


# Список слушающих сокетов без заголовка: tcp+udp, все интерфейсы. bind на
# 0.0.0.0 конфликтует с любым слушателем того же порта (в т.ч. на loopback),
# поэтому адрес не фильтруем — занят значит занят.
_LISTENING_CMD = "ss -Htuln"
# Список портов не должен резаться лимитом вывода OpResult: на сервере может
# быть много слушателей, а потерянная строка — это невидимый занятый порт.
_LISTENING_OUT_MAX = 65536


def parse_listening_ports(output: str) -> set[int]:
    """Разобрать вывод `ss -Htuln` в набор занятых портов.

    Локальный адрес — 5-я колонка (`0.0.0.0:443`, `[::]:443`, `*:443`); порт —
    хвост после последнего двоеточия. Непонятные строки молча пропускаем: лучше
    недосчитаться порта, чем уронить провижн из-за формата вывода."""
    ports: set[int] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        tail = parts[4].rsplit(":", 1)[-1]
        if tail.isdigit():
            ports.add(int(tail))
    return ports


async def listening_ports(
    ip: str, login: str, private_key: str, *, port: int = 22
) -> set[int] | None:
    """Порты, которые на сервере уже кто-то слушает (tcp и udp).

    Нужно раздаче портов инбаундов: занятый чужим процессом (nginx, старая нода)
    порт нельзя отдавать xray — bind упадёт, и инбаунд молча не заработает.
    None — если список снять не удалось (SSH/`ss` недоступны): вызывающий код
    решает сам, падать или раздавать вслепую, как раньше."""
    res = await _connect_run(
        ip, login, private_key, _LISTENING_CMD, port=port,
        out_max=_LISTENING_OUT_MAX,
    )
    if not res.ok:
        logger.warning("listening_ports: не снять порты с %s: %s", ip, res.detail)
        return None
    return parse_listening_ports(res.detail)


def _ufw_allow_cmd(inbound_port: int, *, udp: bool) -> str:
    """Команда открытия порта в UFW. Идемпотентна: ufw allow повторно не плодит
    правил. tcp открываем всегда (как и полный провижн — он открывает tcp всем
    инбаундам); udp=True добавляет правило udp для инбаундов, слушающих и его
    (Shadowsocks — network tcp,udp; Hysteria2 — QUIC). Раньше udp=True заменял
    tcp-правило, и добавленный кнопкой Shadowsocks оставался закрыт по tcp.

    Если UFW на ноде неактивен (например, кастомная нода без него) — `ufw allow`
    всё равно вернёт 0 (правило просто запишется и применится при включении), так
    что отдельный инбаунд это не ломает."""
    cmd = f"ufw allow {int(inbound_port)}/tcp"
    if udp:
        cmd += f" && ufw allow {int(inbound_port)}/udp"
    return cmd


def _ufw_delete_cmd(inbound_port: int, *, udp: bool) -> str:
    """Команда закрытия порта в UFW (обратная _ufw_allow_cmd).

    `ufw delete allow` по несуществующему правилу выходит с кодом 0 («Could not
    delete non-existent rule») — повторное закрытие безопасно."""
    cmd = f"ufw delete allow {int(inbound_port)}/tcp"
    if udp:
        cmd += f" && ufw delete allow {int(inbound_port)}/udp"
    return cmd


async def close_port(
    ip: str, login: str, private_key: str, inbound_port: int, *,
    udp: bool = False, port: int = 22,
) -> OpResult:
    """Закрыть порт инбаунда в UFW ноды (при удалении инбаунда с ноды).

    Зеркально open_port: tcp закрывается всегда, udp=True добавляет udp
    (Hysteria2, Shadowsocks)."""
    res = await _connect_run(
        ip, login, private_key, _ufw_delete_cmd(inbound_port, udp=udp), port=port
    )
    if res.ok:
        proto = "tcp+udp" if udp else "tcp"
        return OpResult(ok=True, detail=f"Порт {inbound_port}/{proto} закрыт.")
    return res


async def open_port(
    ip: str, login: str, private_key: str, inbound_port: int, *,
    udp: bool = False, port: int = 22,
) -> OpResult:
    """Открыть порт инбаунда в UFW ноды (для добавления инбаунда к ноде).

    tcp открывается всегда; udp=True добавляет udp (Hysteria2, Shadowsocks).
    Возвращает OpResult: при сбое подключения — то же понятное «сервер
    недоступен», что и у restart."""
    res = await _connect_run(
        ip, login, private_key, _ufw_allow_cmd(inbound_port, udp=udp), port=port
    )
    if res.ok:
        proto = "tcp+udp" if udp else "tcp"
        return OpResult(ok=True, detail=f"Порт {inbound_port}/{proto} открыт.")
    return res
