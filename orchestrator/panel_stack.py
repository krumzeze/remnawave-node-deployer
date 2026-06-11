"""Генерация секретов и файлов стека панели (compose + Caddy + env).

Стек панели одинаков для обоих вариантов размещения (ADR 0001): remnawave
backend + postgres + redis + caddy. Разница только в том, кто пишет файлы и
запускает compose — на VPS это делает ansible (deploy_panel.yml рендерит
шаблоны), на хосте деплойера эти же файлы рендерит local_compose из строк,
собранных здесь.

Секреты (JWT, пароль БД) генерируются тут один раз и не логируются. Для local
они уходят в env-файл на диск хоста, для vps — в extra-vars ansible (тоже не в
payload очереди). Домен и порт фиксированы контрактом панели: бэкенд слушает
127.0.0.1:3000, Caddy проксирует на него и держит auto-TLS по домену.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

# Имя контейнера бэкенда и порт, на котором он слушает. Совпадает с тем, что
# ждёт Caddy (reverse_proxy remnawave:3000) и официальный образ панели.
BACKEND_SERVICE = "remnawave"
BACKEND_PORT = 3000


def _token(nbytes: int = 32) -> str:
    """URL-safe случайный секрет. 32 байта → ~43 символа base64, хватает для JWT."""
    return secrets.token_urlsafe(nbytes)


def _db_password() -> str:
    """Пароль postgres панели. Без символов, требующих экранирования в URL/env."""
    return secrets.token_hex(24)


@dataclass
class PanelSecrets:
    """Сгенерированные секреты стека панели. В payload очереди не кладутся."""

    jwt_auth_secret: str = field(default_factory=_token)
    jwt_api_tokens_secret: str = field(default_factory=_token)
    metrics_pass: str = field(default_factory=lambda: _token(16))
    postgres_password: str = field(default_factory=_db_password)


def render_env(domain: str, secrets_: PanelSecrets) -> str:
    """Собрать panel.env для бэкенда панели.

    FRONT_END_DOMAIN и SUB_PUBLIC_DOMAIN выводятся из домена оператора:
    фронт — сам домен, публичный адрес подписки — домен + /api/sub (так панель
    отдаёт ссылки подписок наружу). Бэкенд биндится на 127.0.0.1:3000 — наружу
    его публикует только Caddy с TLS, напрямую порт не светим.
    """
    db_url = (
        f"postgresql://remnawave:{secrets_.postgres_password}"
        f"@remnawave-db:5432/remnawave"
    )
    lines = [
        "### Панель Remnawave — сгенерировано деплойером, секреты не редактировать вручную",
        "APP_PORT=3000",
        "",
        f"JWT_AUTH_SECRET={secrets_.jwt_auth_secret}",
        f"JWT_API_TOKENS_SECRET={secrets_.jwt_api_tokens_secret}",
        "",
        f"FRONT_END_DOMAIN={domain}",
        f"SUB_PUBLIC_DOMAIN={domain}/api/sub",
        "",
        "IS_DOCS_ENABLED=false",
        "METRICS_USER=metrics",
        f"METRICS_PASS={secrets_.metrics_pass}",
        "",
        f"DATABASE_URL={db_url}",
        "POSTGRES_USER=remnawave",
        f"POSTGRES_PASSWORD={secrets_.postgres_password}",
        "POSTGRES_DB=remnawave",
        "",
        "REDIS_HOST=remnawave-redis",
        "REDIS_PORT=6379",
        "",
    ]
    return "\n".join(lines)


def render_caddyfile(domain: str) -> str:
    """Caddyfile: auto-TLS по домену, reverse_proxy на бэкенд панели.

    Caddy сам выпускает и продлевает сертификат Let's Encrypt по домену (нужны
    открытые 80/443 и A-запись на этот хост). Проксируем на remnawave:3000 —
    весь внешний трафик панели идёт через TLS, бэкенд наружу не выставлен.
    """
    return (
        f"{domain} {{\n"
        f"    reverse_proxy {BACKEND_SERVICE}:{BACKEND_PORT}\n"
        f"}}\n"
    )


def render_compose() -> str:
    """docker-compose стека панели: backend + postgres + redis + caddy.

    Бэкенд читает env-файл panel.env (секреты из render_env). Caddy слушает
    80/443 и монтирует Caddyfile; его тома хранят сертификаты, чтобы они
    пережили перезапуск. Бэкенд порт наружу не публикуем — только через Caddy.
    """
    return f"""services:
  remnawave:
    image: remnawave/backend:latest
    container_name: remnawave
    hostname: remnawave
    restart: always
    env_file:
      - panel.env
    depends_on:
      remnawave-db:
        condition: service_healthy
      remnawave-redis:
        condition: service_started

  remnawave-db:
    image: postgres:17-alpine
    container_name: remnawave-db
    hostname: remnawave-db
    restart: always
    env_file:
      - panel.env
    volumes:
      - panel-db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U remnawave -d remnawave"]
      interval: 5s
      timeout: 5s
      retries: 10

  remnawave-redis:
    image: redis:7-alpine
    container_name: remnawave-redis
    hostname: remnawave-redis
    restart: always
    volumes:
      - panel-redis:/data

  caddy:
    image: caddy:2-alpine
    container_name: remnawave-caddy
    hostname: remnawave-caddy
    restart: always
    depends_on:
      - remnawave
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - panel-caddy-data:/data
      - panel-caddy-config:/config

volumes:
  panel-db:
  panel-redis:
  panel-caddy-data:
  panel-caddy-config:
"""
