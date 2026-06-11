"""Регистрация супер-админа свежей панели и выпуск долгоживущего API-токена.

Это pre-auth часть разворота панели с нуля (ADR 0001, режим «new»): когда стек
панели только поднялся, у неё ещё нет ни админа, ни токена, поэтому работать
через SDK (он требует готовый токен) нельзя. Здесь — прямые HTTP-запросы к
{panel_url}/api по точному контракту 2.7.1: GET /auth/status, POST /auth/register
или /auth/login, GET/POST /tokens.

Для http (не https) добавляем заголовки x-forwarded-proto/x-forwarded-for —
так же поступает сам SDK, иначе панель за Caddy считает запрос небезопасным.

Граница HTTP инъектируется (`HttpCaller`): по умолчанию это httpx.AsyncClient,
в тестах — фейк без сети, как sdk инъектируется в remnawave_client. Так весь
поток (готовность → регистрация/логин → токен) проверяется без панели.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

# Имя токена, который заводим под деплойер. По нему же ищем уже существующий
# токен при повторном разворачивании (идемпотентность), чтобы не плодить дубли.
TOKEN_NAME = "node-deployer"

# Ожидание готовности панели после docker compose up. Бэкенд поднимается не
# мгновенно (миграции БД, старт сервиса), поэтому /auth/status опрашиваем с
# ретраями. Шов sleep инъектируется, как в tasks.py poll.
READY_ATTEMPTS = 60          # 60 × 5с = 5 минут
READY_INTERVAL_SEC = 5.0


class PanelSetupError(Exception):
    """Шаг настройки панели завершился неуспехом. detail — для отчёта оператору."""


@dataclass
class HttpResponse:
    """Минимальный срез HTTP-ответа, нужный потоку.

    Сознательно не тащим тип httpx.Response наружу: фейку в тестах достаточно
    отдать статус и json, не воспроизводя весь интерфейс httpx.
    """

    status_code: int
    json_body: Any


# Шов HTTP: (method, path, json) → HttpResponse. path — относительный, от
# {panel_url}/api (например "/auth/status"). Реализация по умолчанию — ниже.
HttpCaller = Callable[[str, str, dict | None], Awaitable[HttpResponse]]


def _payload_of(body: Any) -> dict:
    """Достать полезную нагрузку из ответа панели.

    Панель заворачивает ответ в {"response": {...}}; на части эндпоинтов поля
    лежат прямо в корне. Поддерживаем оба варианта, чтобы не зависеть от мелких
    различий формы между версиями."""
    if isinstance(body, dict):
        inner = body.get("response")
        if isinstance(inner, dict):
            return inner
        return body
    return {}


@dataclass
class PanelSetup:
    """Поток pre-auth настройки панели на инъектируемом HTTP-шве."""

    call: HttpCaller
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    ready_attempts: int = READY_ATTEMPTS
    ready_interval_sec: float = READY_INTERVAL_SEC

    async def wait_ready(self) -> dict:
        """Дождаться, пока панель отвечает на GET /auth/status (200).

        Возвращает payload статуса (в нём isRegisterAllowed). Если за отведённые
        попытки 200 так и не пришёл — PanelSetupError, разворот уходит в failed.
        """
        last_detail = "панель не ответила"
        for attempt in range(1, self.ready_attempts + 1):
            try:
                resp = await self.call("GET", "/auth/status", None)
            except Exception as exc:  # noqa: BLE001 — сеть/прокси ещё не готовы
                last_detail = str(exc)
                resp = None
            if resp is not None and resp.status_code == 200:
                return _payload_of(resp.json_body)
            if resp is not None:
                last_detail = f"status={resp.status_code}"
            if attempt < self.ready_attempts:
                await self.sleep(self.ready_interval_sec)
        raise PanelSetupError(
            f"панель не поднялась за {self.ready_attempts} попыток ({last_detail})"
        )

    async def _access_token(self, username: str, password: str, status: dict) -> str:
        """Получить accessToken: регистрация, если админа ещё нет, иначе логин.

        isRegisterAllowed=true означает «админа нет» — регистрируем оператора.
        Иначе панель уже настроена (повторный разворот / ручная настройка) —
        логинимся теми же кредами. Так шаг идемпотентен.
        """
        if status.get("isRegisterAllowed"):
            resp = await self.call(
                "POST", "/auth/register",
                {"username": username, "password": password},
            )
            action = "регистрации админа"
        else:
            resp = await self.call(
                "POST", "/auth/login",
                {"username": username, "password": password},
            )
            action = "входа админом"
        if resp.status_code not in (200, 201):
            raise PanelSetupError(
                f"ошибка {action}: панель ответила {resp.status_code}"
            )
        token = _payload_of(resp.json_body).get("accessToken")
        if not token:
            raise PanelSetupError(f"панель не вернула accessToken при {action}")
        return token

    async def _existing_api_token(self) -> str | None:
        """Найти ранее заведённый API-токен с нашим именем (идемпотентность).

        При повторном разворачивании токен node-deployer уже есть — переиспользуем
        его, а не плодим дубли. Листинг недоступен/упал — возвращаем None, выше
        создадим новый."""
        try:
            resp = await self.call("GET", "/tokens", None)
        except Exception:  # noqa: BLE001 — недоступность листинга не ломает создание
            return None
        if resp.status_code != 200:
            return None
        payload = _payload_of(resp.json_body)
        for item in payload.get("apiKeys") or []:
            if isinstance(item, dict) and item.get("tokenName") == TOKEN_NAME:
                token = item.get("token")
                if token:
                    return token
        return None

    async def _create_api_token(self) -> str:
        """Создать долгоживущий API-токен node-deployer и вернуть его значение."""
        resp = await self.call("POST", "/tokens", {"tokenName": TOKEN_NAME})
        if resp.status_code not in (200, 201):
            raise PanelSetupError(
                f"не удалось создать API-токен: панель ответила {resp.status_code}"
            )
        token = _payload_of(resp.json_body).get("token")
        if not token:
            raise PanelSetupError("панель не вернула token при создании API-токена")
        return token

    async def provision(self, username: str, password: str) -> str:
        """Полный поток: дождаться панели, зарегистрировать/войти, выдать токен.

        Возвращает значение долгоживущего API-токена — его кладём в Vault как
        токен «существующей» панели, дальше ноды добавляются обычным флоу.

        accessToken в контракт HttpCaller не входит: боевой шов запоминает его из
        ответа register/login и сам добавляет Authorization на шаге /tokens (см.
        _build_authed_caller). Поток остаётся проверяемым на фейке без сети.
        """
        status = await self.wait_ready()
        await self._access_token(username, password, status)
        existing = await self._existing_api_token()
        if existing:
            logger.info("API-токен %s уже есть — переиспользую", TOKEN_NAME)
            return existing
        return await self._create_api_token()


async def provision_panel_admin(
    panel_url: str,
    username: str,
    password: str,
    *,
    call: HttpCaller | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ready_attempts: int = READY_ATTEMPTS,
    ready_interval_sec: float = READY_INTERVAL_SEC,
) -> str:
    """Удобная точка входа: собрать PanelSetup и прогнать поток.

    call по умолчанию — боевой httpx-шов на {panel_url}/api. В тестах передаётся
    фейк, и сеть не трогается. Возвращает долгоживущий API-токен панели.
    """
    caller = call or _build_authed_caller(panel_url)
    setup = PanelSetup(
        call=caller, sleep=sleep,
        ready_attempts=ready_attempts, ready_interval_sec=ready_interval_sec,
    )
    return await setup.provision(username, password)


def _build_authed_caller(panel_url: str) -> HttpCaller:
    """Боевой HTTP-шов, который сам подставляет Bearer после логина.

    Регистрация/логин Bearer не требуют; для /tokens нужен accessToken из
    предыдущего шага. Шов запоминает accessToken из ответов register/login и
    добавляет его в Authorization на последующих вызовах — так контракт
    HttpCaller остаётся узким (метод, путь, тело), а авторизацию ведёт сам шов.
    """
    import httpx

    base = panel_url.rstrip("/") + "/api"
    headers = {"Content-Type": "application/json"}
    if base.startswith("http://"):
        headers["x-forwarded-proto"] = "https"
        headers["x-forwarded-for"] = "127.0.0.1"

    state: dict[str, str | None] = {"access_token": None}

    async def call(method: str, path: str, json: dict | None) -> HttpResponse:
        hdrs = dict(headers)
        if state["access_token"]:
            hdrs["Authorization"] = f"Bearer {state['access_token']}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(method, base + path, json=json, headers=hdrs)
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001 — не-JSON ответ (502 от прокси и т.п.)
            body = None
        # Запоминаем accessToken для последующего шага /tokens.
        token = _payload_of(body).get("accessToken")
        if token:
            state["access_token"] = token
        return HttpResponse(status_code=resp.status_code, json_body=body)

    return call
