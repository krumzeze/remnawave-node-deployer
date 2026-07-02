"""Тесты SSH-действий над нодой (orchestrator/node_ops.py, ADR 0013).

Реального SSH нет: подменяем asyncssh.connect/import_private_key фейками и
проверяем, что restart/reboot шлют верную команду, а сбой подключения
превращается в понятное «сервер недоступен», отделённое от сбоя команды.
"""
from __future__ import annotations

import pytest

from orchestrator import node_ops


class FakeRun:
    def __init__(self, exit_status=0, stdout="", stderr=""):
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr


class FakeConn:
    def __init__(self, run_result):
        self._r = run_result
        self.cmd = None
        self.closed = False

    async def run(self, cmd, check=False):
        self.cmd = cmd
        return self._r

    def close(self):
        self.closed = True


@pytest.fixture
def patch_ssh(monkeypatch):
    """Подменить asyncssh: connect отдаёт заданный FakeConn, ключ не парсим."""

    def _apply(conn=None, raise_connect=None):
        monkeypatch.setattr(node_ops.asyncssh, "import_private_key", lambda k: k)

        async def fake_connect(ip, **kw):
            if raise_connect is not None:
                raise raise_connect
            return conn

        monkeypatch.setattr(node_ops.asyncssh, "connect", fake_connect)
        return conn

    return _apply


@pytest.mark.asyncio
async def test_restart_node_runs_docker_restart(patch_ssh):
    conn = FakeConn(FakeRun(exit_status=0, stdout="remnanode"))
    patch_ssh(conn=conn)

    res = await node_ops.restart_node("1.2.3.4", "root", "PRIV")
    assert res.ok
    assert conn.cmd == "docker restart remnanode"
    assert conn.closed


@pytest.mark.asyncio
async def test_reboot_server_sends_background_reboot(patch_ssh):
    conn = FakeConn(FakeRun(exit_status=0))
    patch_ssh(conn=conn)

    res = await node_ops.reboot_server("1.2.3.4", "root", "PRIV")
    assert res.ok
    assert "reboot" in conn.cmd
    assert "перезагрузк" in res.detail.lower()


@pytest.mark.asyncio
async def test_connect_failure_is_unreachable(patch_ssh):
    patch_ssh(raise_connect=OSError("no route"))

    res = await node_ops.restart_node("1.2.3.4", "root", "PRIV")
    assert res.ok is False
    assert "недоступен" in res.detail


@pytest.mark.asyncio
async def test_command_nonzero_exit_reports_stderr(patch_ssh):
    conn = FakeConn(FakeRun(exit_status=1, stderr="No such container: remnanode"))
    patch_ssh(conn=conn)

    res = await node_ops.restart_node("1.2.3.4", "root", "PRIV")
    assert res.ok is False
    assert "No such container" in res.detail


_SS_OUTPUT = """\
tcp   LISTEN 0      128        0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      511        0.0.0.0:443       0.0.0.0:*
tcp   LISTEN 0      511           [::]:443          [::]:*
tcp   LISTEN 0      4096     127.0.0.1:8443      0.0.0.0:*
udp   UNCONN 0      0        127.0.0.53%lo:53    0.0.0.0:*
tcp   LISTEN 0      128              *:2222            *:*
битая строка
"""


def test_parse_listening_ports():
    # Порт — хвост локального адреса (ipv4/ipv6/*); loopback тоже считается
    # занятым (bind 0.0.0.0 конфликтует с ним); мусорные строки пропускаются.
    ports = node_ops.parse_listening_ports(_SS_OUTPUT)
    assert ports == {22, 443, 8443, 53, 2222}


@pytest.mark.asyncio
async def test_listening_ports_runs_ss(patch_ssh):
    conn = FakeConn(FakeRun(exit_status=0, stdout=_SS_OUTPUT))
    patch_ssh(conn=conn)

    ports = await node_ops.listening_ports("1.2.3.4", "root", "PRIV")
    assert conn.cmd == "ss -Htuln"
    assert 443 in ports and 8443 in ports


@pytest.mark.asyncio
async def test_listening_ports_none_on_failure(patch_ssh):
    # Команда упала (нет ss/нет прав) → None, а не пустой набор: вызывающий код
    # должен отличать «не узнали» от «всё свободно».
    conn = FakeConn(FakeRun(exit_status=127, stderr="ss: not found"))
    patch_ssh(conn=conn)

    assert await node_ops.listening_ports("1.2.3.4", "root", "PRIV") is None


def test_ufw_delete_cmd_tcp_and_udp():
    # Зеркально _ufw_allow_cmd: tcp всегда, udp добавляется вторым правилом.
    assert node_ops._ufw_delete_cmd(8443, udp=False) == "ufw delete allow 8443/tcp"
    assert node_ops._ufw_delete_cmd(443, udp=True) == (
        "ufw delete allow 443/tcp && ufw delete allow 443/udp"
    )


@pytest.mark.asyncio
async def test_close_port_runs_ufw_delete(patch_ssh):
    conn = FakeConn(FakeRun(exit_status=0))
    patch_ssh(conn=conn)

    res = await node_ops.close_port("1.2.3.4", "root", "PRIV", 8443)
    assert res.ok
    assert conn.cmd == "ufw delete allow 8443/tcp"
    assert "закрыт" in res.detail


def test_ufw_allow_cmd_tcp_and_udp():
    # tcp открывается всегда; udp=True добавляет udp-правило, не заменяя tcp
    # (Shadowsocks слушает tcp,udp — раньше tcp оставался закрыт).
    assert node_ops._ufw_allow_cmd(8443, udp=False) == "ufw allow 8443/tcp"
    assert node_ops._ufw_allow_cmd(443, udp=True) == (
        "ufw allow 443/tcp && ufw allow 443/udp"
    )


@pytest.mark.asyncio
async def test_open_port_udp_runs_ufw(patch_ssh):
    conn = FakeConn(FakeRun(exit_status=0))
    patch_ssh(conn=conn)

    res = await node_ops.open_port("1.2.3.4", "root", "PRIV", 443, udp=True)
    assert res.ok
    assert conn.cmd == "ufw allow 443/tcp && ufw allow 443/udp"
    assert "443/tcp+udp" in res.detail
