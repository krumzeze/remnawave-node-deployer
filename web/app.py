"""Веб-дашборд: статус нод и аудит (наряду с Telegram).

Скелет на FastAPI. Эндпоинты-заглушки, реальная выборка из БД — TODO.
"""
from fastapi import FastAPI

app = FastAPI(title="remnawave-node-deployer")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/nodes")
async def list_nodes() -> list[dict]:
    # TODO: выборка нод владельца из БД со статусами
    return []


@app.get("/nodes/{node_id}/audit")
async def node_audit(node_id: int) -> list[dict]:
    # TODO: аудит-лог по ноде для владельца сервера
    return []
