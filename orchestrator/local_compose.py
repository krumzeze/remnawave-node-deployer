"""Локальный разворот стека панели на хосте деплойера (вариант «local»).

Когда оператор выбрал размещение панели «на хосте деплойера» (а не на отдельном
VPS), SSH не нужен: docker compose выполняется прямо на машине, где крутится
деплойер. Воркер сам в контейнере, поэтому docker мы дёргаем через смонтированный
docker-сокет хоста (см. docker-compose.yml деплойера, опциональный mount
/var/run/docker.sock) — `docker compose` обращается к демону хоста и поднимает
стек панели рядом, а не внутри воркера.

Файлы стека (compose, Caddyfile, env) пишем в каталог из настройки
panel_local_dir и запускаем `docker compose up -d`. Запуск subprocess вынесен в
инъектируемый шов (`Runner`), чтобы тесты проверяли сборку файлов и команды без
реального docker.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


class LocalComposeError(Exception):
    """Сбой локального разворота стека панели. detail — для отчёта оператору."""


@dataclass
class RunResult:
    """Итог запуска внешней команды (срез CompletedProcess, нужный нам)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


# Шов запуска команды: (argv, cwd) → RunResult. По умолчанию — subprocess.run;
# в тестах подменяется фейком, чтобы не звать docker.
Runner = Callable[[list[str], str], RunResult]


def _default_runner(argv: list[str], cwd: str) -> RunResult:
    """Боевой запуск через subprocess.run. docker compose долгий (тянет образы),
    поэтому таймаут щедрый. Вывод собираем для понятной ошибки оператору."""
    proc = subprocess.run(
        argv, cwd=cwd, capture_output=True, text=True, timeout=900
    )
    return RunResult(
        returncode=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or ""
    )


# Имена файлов стека внутри panel_local_dir. compose ссылается на Caddyfile и env
# относительно своего каталога — кладём всё рядом.
COMPOSE_FILE = "docker-compose.yml"
CADDYFILE = "Caddyfile"
ENV_FILE = "panel.env"


@dataclass
class LocalCompose:
    """Запись файлов стека панели и запуск compose на хосте деплойера."""

    base_dir: str
    runner: Runner = _default_runner

    def write_stack(self, compose: str, caddyfile: str, env: str) -> str:
        """Разложить файлы стека в base_dir/<owner-каталог>. Возвращает путь каталога.

        Каталог создаётся при отсутствии. Файлы перезаписываются — повторный
        разворот должен обновлять стек, а не падать. env с секретами кладём с
        правами 600 (в нём JWT и пароль БД), остальное обычным режимом.
        """
        target = Path(self.base_dir)
        try:
            target.mkdir(parents=True, exist_ok=True)
            (target / COMPOSE_FILE).write_text(compose, encoding="utf-8")
            (target / CADDYFILE).write_text(caddyfile, encoding="utf-8")
            env_path = target / ENV_FILE
            env_path.write_text(env, encoding="utf-8")
            try:
                env_path.chmod(0o600)
            except OSError:  # noqa: PERF203 — chmod не везде доступен (например на mount)
                pass
        except OSError as exc:
            raise LocalComposeError(
                f"не удалось записать файлы стека панели в {target}: {exc}"
            ) from exc
        return str(target)

    def up(self, cwd: str) -> None:
        """Поднять стек: docker compose up -d. Сбой → LocalComposeError с выводом.

        --env-file задаём явно: имя panel.env не дефолтное (.env), иначе compose
        не подхватит переменные. -d, чтобы не блокировать воркер на foreground.
        """
        argv = [
            "docker", "compose",
            "--env-file", ENV_FILE,
            "up", "-d",
        ]
        try:
            result = self.runner(argv, cwd)
        except Exception as exc:  # noqa: BLE001 — docker недоступен/сокет не смонтирован
            raise LocalComposeError(
                f"не удалось запустить docker compose: {exc}"
            ) from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise LocalComposeError(
                f"docker compose up завершился с кодом {result.returncode}: {detail}"
            )
        logger.info("локальный стек панели поднят в %s", cwd)
