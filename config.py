"""Единая конфигурация из окружения (.env)."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    bot_token: str = ""

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

    web_host: str = "0.0.0.0"
    web_port: int = 8000

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
