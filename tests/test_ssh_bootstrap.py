from orchestrator.ssh_bootstrap import (
    Environment,
    _evaluate_environment,
    _generate_keypair,
)


def _env(os_id="ubuntu", os_version="22.04", virt="kvm", kernel="5.15.0"):
    return Environment(os_id=os_id, os_version=os_version, virt=virt, kernel=kernel)


def test_supported_ubuntu_kvm_passes():
    ok, reason = _evaluate_environment(_env(os_version="22.04"))
    assert ok and reason == ""
    ok, _ = _evaluate_environment(_env(os_version="24.04"))
    assert ok


def test_wrong_os_rejected():
    ok, reason = _evaluate_environment(_env(os_id="debian"))
    assert not ok and "debian" in reason


def test_wrong_version_rejected():
    ok, reason = _evaluate_environment(_env(os_version="20.04"))
    assert not ok and "20.04" in reason


def test_container_virt_rejected():
    for virt in ("openvz", "lxc", "docker"):
        ok, reason = _evaluate_environment(_env(virt=virt))
        assert not ok and virt in reason


def test_bare_metal_and_kvm_pass():
    # systemd-detect-virt на железе печатает "none" — это не контейнер, ок.
    assert _evaluate_environment(_env(virt="none"))[0]
    assert _evaluate_environment(_env(virt="kvm"))[0]


def test_generate_keypair_shape():
    private_pem, public_line = _generate_keypair()
    assert "PRIVATE KEY" in private_pem
    assert public_line.startswith("ssh-ed25519 ")
    # Два независимых вызова дают разные ключи.
    assert _generate_keypair()[0] != private_pem
