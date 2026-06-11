"""Тесты локального разворота стека панели (orchestrator/local_compose).

docker не трогаем: запуск команды вынесен в инъектируемый шов runner, в тестах —
фейк. Проверяем, что файлы стека пишутся в каталог, а up зовёт docker compose с
нужными аргументами и поднимает ошибку при ненулевом коде возврата.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.local_compose import (
    CADDYFILE,
    COMPOSE_FILE,
    ENV_FILE,
    LocalCompose,
    LocalComposeError,
    RunResult,
)


def test_write_stack_writes_all_files(tmp_path):
    base = tmp_path / "panel"
    stack = LocalCompose(base_dir=str(base))
    cwd = stack.write_stack("compose-body", "caddy-body", "env-body")

    assert Path(cwd) == base
    assert (base / COMPOSE_FILE).read_text(encoding="utf-8") == "compose-body"
    assert (base / CADDYFILE).read_text(encoding="utf-8") == "caddy-body"
    assert (base / ENV_FILE).read_text(encoding="utf-8") == "env-body"


def test_up_invokes_docker_compose():
    calls = []

    def runner(argv, cwd):
        calls.append((argv, cwd))
        return RunResult(returncode=0)

    stack = LocalCompose(base_dir="/tmp/x", runner=runner)
    stack.up("/tmp/x")

    assert len(calls) == 1
    argv, cwd = calls[0]
    assert argv[:2] == ["docker", "compose"]
    assert "up" in argv and "-d" in argv
    # env-файл задаётся явно (имя не дефолтное .env).
    assert "--env-file" in argv and ENV_FILE in argv
    assert cwd == "/tmp/x"


def test_up_raises_on_nonzero_returncode():
    def runner(argv, cwd):
        return RunResult(returncode=1, stderr="boom")

    stack = LocalCompose(base_dir="/tmp/x", runner=runner)
    with pytest.raises(LocalComposeError) as exc:
        stack.up("/tmp/x")
    assert "boom" in str(exc.value)


def test_up_raises_when_runner_throws():
    def runner(argv, cwd):
        raise FileNotFoundError("docker not found")

    stack = LocalCompose(base_dir="/tmp/x", runner=runner)
    with pytest.raises(LocalComposeError):
        stack.up("/tmp/x")
