"""Проверка домена перед выпуском TLS-сертификата (ADR 0005).

TLS-инбаунду нужен сертификат, а сертификат по HTTP-01 выпускается только если
домен уже указывает на ноду. Поэтому до выпуска делаем гейт: резолвим домен и
сверяем, что хотя бы одна его A-запись совпадает с IP ноды. Если оператор ещё
не создал A-запись (или DNS не прокатился) — выпуск не запускаем и говорим об
этом понятно, а не упираемся в невнятную ошибку acme.sh (принцип «не навреди»,
ср. [[0002-auth-fork]]).

Модуль держим без побочной сети по умолчанию только в тестах: резолвер
инъектируется, в проде это системный DNS через socket.getaddrinfo, вынесенный
в поток (он блокирующий).
"""
from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable

# Резолвер: домен → список IP (строки). По умолчанию системный DNS; в тестах
# подменяется на фейк, чтобы не ходить в сеть.
Resolver = Callable[[str], Awaitable[list[str]]]

# Имя хоста: метки a-z0-9-, точкой разделены, TLD из букв. Без подчёркиваний и
# без завершающей точки — этого достаточно, чтобы отсечь явный мусор в боте.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


@dataclass
class DomainCheck:
    """Итог проверки домена.

    ok — указывает ли домен на нужный IP. resolved — что вернул DNS (для
    понятного сообщения оператору: «домен смотрит на X, а нода — Y»).
    """

    ok: bool
    detail: str
    resolved: list[str] = field(default_factory=list)


def normalize_domain(raw: str) -> str:
    """Привести ввод к канону: обрезать пробелы, схему и завершающую точку,
    привести к нижнему регистру. Возвращает пустую строку для явного мусора."""
    s = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.split("/", 1)[0]      # отрезаем путь, если вставили URL целиком
    s = s.rstrip(".")           # FQDN с завершающей точкой → без неё
    return s


def is_valid_domain(domain: str) -> bool:
    """Похоже ли на доменное имя. Не проверяет существование — только формат."""
    return bool(_DOMAIN_RE.match(domain))


async def _system_resolver(domain: str) -> list[str]:
    """A-записи домена через системный DNS. getaddrinfo блокирующий, поэтому
    исполняется в отдельном потоке, чтобы не вешать воркер очереди."""
    def _lookup() -> list[str]:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET,
                                   type=socket.SOCK_STREAM)
        # getaddrinfo даёт дубли (по одному на тип сокета) — уникализируем.
        return sorted({info[4][0] for info in infos})

    try:
        return await asyncio.to_thread(_lookup)
    except socket.gaierror:
        return []


async def check_points_to(
    domain: str,
    expected_ip: str,
    *,
    resolver: Resolver | None = None,
) -> DomainCheck:
    """Проверить, что домен резолвится на IP ноды.

    Сначала валидируем формат (плохой ввод не доводим до DNS), затем резолвим и
    сверяем с expected_ip. ok=True только при точном совпадении хотя бы одной
    A-записи: частичное совпадение или пустой ответ — это «ещё не указывает».
    """
    if not is_valid_domain(domain):
        return DomainCheck(ok=False, detail=f"некорректное доменное имя: {domain!r}")

    resolve = resolver or _system_resolver
    resolved = await resolve(domain)

    if not resolved:
        return DomainCheck(
            ok=False,
            detail=f"домен {domain} не резолвится — создана ли A-запись?",
        )
    if expected_ip in resolved:
        return DomainCheck(
            ok=True,
            detail=f"{domain} → {expected_ip}",
            resolved=resolved,
        )
    return DomainCheck(
        ok=False,
        detail=(
            f"{domain} указывает на {', '.join(resolved)}, а нужен {expected_ip}: "
            "поправь A-запись и подожди обновления DNS"
        ),
        resolved=resolved,
    )
