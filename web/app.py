"""Веб-дашборд: статус нод и аудит (наряду с Telegram).

Доступ по подписанному токену (ADR 0014): бот выдаёт пользователю персональную
ссылку, веб проверяет HMAC-подпись и извлекает owner_tg_id из неё. Сырой
owner_tg_id из запроса больше не принимается — иначе любой перебрал бы чужие id.
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.ext.asyncio import async_sessionmaker

from config import settings
from db import repo
from web.auth import verify_token

app = FastAPI(title="remnawave-node-deployer")


def _get_session_factory() -> async_sessionmaker:
    """Боевая фабрика сессий. Переопределяется в тестах через dependency_overrides."""
    from db import get_sessionmaker
    return get_sessionmaker()


def _get_web_secret() -> str:
    """Секрет подписи токенов. Отдельная зависимость — чтобы подменять в тестах."""
    return settings.web_secret


async def current_owner(
    token: str = Query(..., description="Подписанный токен доступа из бота"),
    secret: str = Depends(_get_web_secret),
) -> int:
    """owner_tg_id из проверенного токена, иначе HTTP-ошибка.

    Секрет не задан → 503 (веб-аутентификация не настроена). Токен битый или
    просрочен → 401. Так эндпойнты работают только с доверенной личностью."""
    if not secret:
        raise HTTPException(status_code=503, detail="web auth not configured")
    owner = verify_token(token, secret)
    if owner is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return owner


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/nodes")
async def list_nodes(
    owner_tg_id: int = Depends(current_owner),
    sf: async_sessionmaker = Depends(_get_session_factory),
) -> list[dict]:
    """Список нод владельца со статусами. Владелец — из проверенного токена."""
    nodes = await repo.list_nodes_for_owner(sf, owner_tg_id)
    return [
        {
            "id": n.id,
            "ip": n.ip,
            "state": n.state,
            "remnawave_uuid": n.remnawave_uuid,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in nodes
    ]


@app.get("/nodes/{node_id}/audit")
async def node_audit(
    node_id: int,
    owner_tg_id: int = Depends(current_owner),
    sf: async_sessionmaker = Depends(_get_session_factory),
) -> list[dict]:
    """История переходов состояний ноды.

    Если нода не принадлежит владельцу — пустой список, не 404: не раскрываем
    факт существования чужой ноды.
    """
    return await repo.list_node_audit(sf, node_id, owner_tg_id)
