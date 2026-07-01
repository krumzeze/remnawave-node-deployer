"""Единая конфигурация из окружения (.env)."""
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    bot_token: str = ""

    # Админы бота: строка вида "111,222" из .env (ADMIN_TELEGRAM_IDS). Это НЕ
    # барьер доступа (регистрация открытая, ADR 0014), а привилегия: выдача
    # подписки вручную, служебные команды. Пустая строка = админов нет. Разбор
    # в множество int — в свойстве admin_telegram_ids.
    admin_telegram_ids_raw: str = Field(
        default="",
        validation_alias=AliasChoices(
            "ADMIN_TELEGRAM_IDS", "admin_telegram_ids_raw"
        ),
    )

    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "nodeforge"
    postgres_user: str = "nodeforge"
    postgres_password: str = ""

    redis_host: str = "redis"
    redis_port: int = 6379

    vault_addr: str = "http://vault:8200"
    vault_token: str = ""
    vault_kv_mount: str = "secret"

    # Мультитенант (ADR 0014): панель у каждого тенанта своя (BYO), её URL/токен
    # хранятся per-owner (Panel + Vault). Глобальной панели оператора больше нет,
    # чтобы чужая нода не могла уйти в неё под токеном оператора.

    # Каталог на хосте деплойера, куда пишутся файлы стека панели при локальном
    # разворачивании (вариант «local», ADR 0001). docker compose там же и
    # запускается через смонтированный docker-сокет хоста. Для варианта «vps»
    # не используется. Пустая строка = фолбэк на дефолт ниже.
    panel_local_dir: str = "/opt/remnawave-panel"

    # Временный тумблер сценария «развернуть панель с нуля» (ADR 0001/0011).
    # Пока нет возможности прогнать разворот на живом сервере, прячем кнопку
    # в боте и блокируем сценарий, оставляя код мастера на месте. Включить
    # обратно: PANEL_FROM_SCRATCH_ENABLED=true в .env (или дефолт ниже на True).
    panel_from_scratch_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "PANEL_FROM_SCRATCH_ENABLED", "panel_from_scratch_enabled"
        ),
    )

    web_host: str = "0.0.0.0"
    web_port: int = 8000

    # Публичный базовый URL дашборда — из него бот собирает персональную ссылку
    # (например https://dash.example.com). Пустая строка = ссылку не показываем.
    web_base_url: str = ""

    # Секрет подписи токенов доступа к дашборду (ADR 0014). Веб пускает не по
    # сырому owner_tg_id, а по HMAC-подписанному токену, который выдаёт бот.
    # Пустая строка = веб-аутентификация не настроена и API отдаёт 503.
    web_secret: str = ""

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def admin_telegram_ids(self) -> set[int]:
        """ID Telegram админов бота. Разбираем строку по запятым, пустые и
        нечисловые токены пропускаем. Пустой результат — админов нет."""
        result: set[int] = set()
        for token in self.admin_telegram_ids_raw.split(","):
            token = token.strip()
            if token:
                try:
                    result.add(int(token))
                except ValueError:
                    continue
        return result


settings = Settings()
