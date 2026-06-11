"""Тесты pre-auth настройки панели (orchestrator/panel_setup) на фейковом HTTP.

Сеть не трогаем: HttpCaller подменяется фейком, который отдаёт заранее заданные
ответы. Проверяем регистрацию, когда админа ещё нет; логин, когда регистрация
закрыта; переиспользование уже существующего токена; и ретраи ожидания
готовности панели.
"""
from __future__ import annotations

import pytest

from orchestrator import panel_setup
from orchestrator.panel_setup import HttpResponse, PanelSetup, PanelSetupError


class _FakeHttp:
    """Фейковый HTTP-шов: отвечает по (method, path) из заданной таблицы.

    Для путей со списком ответов отдаёт их по очереди (последний повторяется) —
    так моделируем «панель ещё не готова, потом готова». Записывает все вызовы.
    """

    def __init__(self, routes: dict):
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls: list[tuple[str, str, dict | None]] = []

    async def __call__(self, method: str, path: str, json):
        self.calls.append((method, path, json))
        queue = self.routes[(method, path)]
        return queue.pop(0) if len(queue) > 1 else queue[0]


async def _no_sleep(_):
    return None


@pytest.mark.asyncio
async def test_register_when_register_allowed():
    # Админа ещё нет (isRegisterAllowed) → регистрируем, потом выдаём токен.
    http = _FakeHttp({
        ("GET", "/auth/status"): [HttpResponse(200, {"isRegisterAllowed": True})],
        ("POST", "/auth/register"): [HttpResponse(201, {"accessToken": "acc"})],
        ("GET", "/tokens"): [HttpResponse(200, {"apiKeys": []})],
        ("POST", "/tokens"): [HttpResponse(201, {"token": "api-tok", "uuid": "u1"})],
    })
    setup = PanelSetup(call=http, sleep=_no_sleep, ready_attempts=3)
    token = await setup.provision("admin", "Passw0rd" * 4)

    assert token == "api-tok"
    paths = [(m, p) for m, p, _ in http.calls]
    assert ("POST", "/auth/register") in paths
    assert ("POST", "/auth/login") not in paths
    assert ("POST", "/tokens") in paths


@pytest.mark.asyncio
async def test_login_when_register_not_allowed():
    # Регистрация закрыта (админ уже есть) → логинимся, не регистрируем.
    http = _FakeHttp({
        ("GET", "/auth/status"): [HttpResponse(200, {"isRegisterAllowed": False})],
        ("POST", "/auth/login"): [HttpResponse(200, {"accessToken": "acc"})],
        ("GET", "/tokens"): [HttpResponse(200, {"apiKeys": []})],
        ("POST", "/tokens"): [HttpResponse(200, {"token": "api-tok"})],
    })
    setup = PanelSetup(call=http, sleep=_no_sleep, ready_attempts=3)
    token = await setup.provision("admin", "Passw0rd" * 4)

    assert token == "api-tok"
    paths = [(m, p) for m, p, _ in http.calls]
    assert ("POST", "/auth/login") in paths
    assert ("POST", "/auth/register") not in paths


@pytest.mark.asyncio
async def test_reuses_existing_token():
    # Токен с нашим именем уже есть → переиспользуем, POST /tokens не зовём.
    http = _FakeHttp({
        ("GET", "/auth/status"): [HttpResponse(200, {"isRegisterAllowed": False})],
        ("POST", "/auth/login"): [HttpResponse(200, {"accessToken": "acc"})],
        ("GET", "/tokens"): [HttpResponse(200, {
            "apiKeys": [
                {"uuid": "x", "tokenName": "other", "token": "nope"},
                {"uuid": "y", "tokenName": panel_setup.TOKEN_NAME, "token": "existing"},
            ]
        })],
    })
    setup = PanelSetup(call=http, sleep=_no_sleep, ready_attempts=3)
    token = await setup.provision("admin", "Passw0rd" * 4)

    assert token == "existing"
    paths = [(m, p) for m, p, _ in http.calls]
    assert ("POST", "/tokens") not in paths


@pytest.mark.asyncio
async def test_wait_ready_retries_until_200():
    # Первые два опроса — 502 (панель ещё поднимается), третий 200. wait_ready
    # должна дотерпеть и вернуть payload статуса, поспав между попытками.
    slept = []

    async def sleep(sec):
        slept.append(sec)

    http = _FakeHttp({
        ("GET", "/auth/status"): [
            HttpResponse(502, None),
            HttpResponse(502, None),
            HttpResponse(200, {"isRegisterAllowed": True}),
        ],
    })
    setup = PanelSetup(call=http, sleep=sleep, ready_attempts=5, ready_interval_sec=1.0)
    status = await setup.wait_ready()

    assert status == {"isRegisterAllowed": True}
    assert len(slept) == 2  # поспали ровно между тремя попытками


@pytest.mark.asyncio
async def test_wait_ready_gives_up_after_attempts():
    http = _FakeHttp({
        ("GET", "/auth/status"): [HttpResponse(503, None)],
    })
    setup = PanelSetup(call=http, sleep=_no_sleep, ready_attempts=3)
    with pytest.raises(PanelSetupError):
        await setup.wait_ready()


@pytest.mark.asyncio
async def test_response_unwraps_nested_response_field():
    # Панель может заворачивать тело в {"response": {...}} — поток это понимает.
    http = _FakeHttp({
        ("GET", "/auth/status"): [HttpResponse(200, {"response": {"isRegisterAllowed": True}})],
        ("POST", "/auth/register"): [HttpResponse(201, {"response": {"accessToken": "acc"}})],
        ("GET", "/tokens"): [HttpResponse(200, {"response": {"apiKeys": []}})],
        ("POST", "/tokens"): [HttpResponse(201, {"response": {"token": "wrapped-tok"}})],
    })
    setup = PanelSetup(call=http, sleep=_no_sleep, ready_attempts=3)
    token = await setup.provision("admin", "Passw0rd" * 4)
    assert token == "wrapped-tok"
