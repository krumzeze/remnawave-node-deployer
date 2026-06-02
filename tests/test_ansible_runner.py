"""Тесты обёртки над ansible-runner на фейковом runner.

Реального ansible и сервера нет: подменяется только граница `ansible_runner.run`
(параметр `runner`). Проверяем, что инвентарь и vars собраны правильно и что
rc/status корректно сводятся к ok.
"""
from __future__ import annotations

import types

import pytest

from orchestrator import ansible_runner as ar


def _fake_result(rc=0, status="successful"):
    return types.SimpleNamespace(rc=rc, status=status)


@pytest.mark.asyncio
async def test_run_playbook_passes_inventory_and_vars():
    captured = {}

    def fake_runner(**kwargs):
        captured.update(kwargs)
        return _fake_result()

    res = await ar.run_playbook(
        "/pb/deploy.yml",
        "1.2.3.4",
        "root",
        "PRIVKEY",
        port=2222,
        extra_vars={"remnanode_port": 2222},
        runner=fake_runner,
    )

    assert res.ok is True
    assert res.rc == 0
    # Инвентарь: один хост с нужными параметрами подключения.
    inv = captured["inventory"]
    assert "ansible_host=1.2.3.4" in inv
    assert "ansible_user=root" in inv
    assert "ansible_port=2222" in inv
    assert captured["ssh_key"] == "PRIVKEY"
    assert captured["extravars"] == {"remnanode_port": 2222}
    assert captured["host_pattern"] == ar.INVENTORY_HOST
    assert captured["envvars"]["ANSIBLE_HOST_KEY_CHECKING"] == "False"


@pytest.mark.asyncio
async def test_run_playbook_failure_status():
    res = await ar.run_playbook(
        "/pb/deploy.yml", "1.2.3.4", "root", "PRIVKEY",
        runner=lambda **k: _fake_result(rc=2, status="failed"),
    )
    assert res.ok is False
    assert res.rc == 2
    assert "failed" in res.detail


@pytest.mark.asyncio
async def test_run_playbook_nonzero_rc_with_successful_status_is_failure():
    # Защита: ok только при rc==0 И status=="successful".
    res = await ar.run_playbook(
        "/pb/deploy.yml", "1.2.3.4", "root", "PRIVKEY",
        runner=lambda **k: _fake_result(rc=1, status="successful"),
    )
    assert res.ok is False
