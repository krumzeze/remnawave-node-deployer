"""Единая конфигурация из окружения (.env)."""
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    bot_token: str = ""

    # Белый список владельцев бота: строка вида "111,222" из .env
    # (ALLOWED_TELEGRAM_IDS). Пустая строка = список пуст, и бот считается
    # ненастроенным (никого не пускает) — см. bot/access.py. Разбор в множество
    # int — в свойстве allowed_telegram_ids.
    allowed_telegram_ids_raw: str = Field(
        default="",
        validation_alias=AliasChoices(
            "ALLOWED_TELEGRAM_IDS", "allowed_telegram_ids_raw"
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

    remnawave_panel_url: str = ""
    remnawave_api_token: str = ""

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

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def allowed_telegram_ids(self) -> set[int]:
        """ID Telegram, которым разрешён бот. Разбираем строку по запятым,
        пустые и нечисловые токены пропускаем. Пустой результат — бот закрыт
        для всех (ненастроен)."""
        result: set[int] = set()
        for token in self.allowed_telegram_ids_raw.split(","):
            token = token.strip()
            if token:
                try:
                    result.add(int(token))
                except ValueError:
                    continue
        return result


settings = Settings()
