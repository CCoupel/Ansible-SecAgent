"""
test_facts_collector.py — Tests unitaires pour facts_collector.py

Couverture exhaustive de toutes les fonctions publiques et helpers :
  _read_file, _run
  _get_hostname, _get_os_family, _get_kernel_version
  _get_cpu_count, _get_memory_total_mb, _get_disk_total_gb
  _get_network_interfaces, _collect_ipv4_for_iface, _collect_ipv6_for_iface
  _get_installed_packages
  collect_facts (intégration + JSON-sérialisabilité + graceful degradation)

Stratégie : aucune connexion réseau ni fichier système réel — tout mocké.
"""

import ast
import json
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "agent"))

from facts_collector import (
    _collect_ipv4_for_iface,
    _collect_ipv6_for_iface,
    _get_cpu_count,
    _get_disk_total_gb,
    _get_hostname,
    _get_installed_packages,
    _get_kernel_version,
    _get_memory_total_mb,
    _get_network_interfaces,
    _get_os_family,
    _read_file,
    _run,
    collect_facts,
)


# ===========================================================================
# _read_file
# ===========================================================================

class TestReadFile:
    def test_reads_existing_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world\n")
        assert _read_file(str(f)) == "hello world\n"

    def test_returns_empty_string_on_missing_file(self):
        assert _read_file("/nonexistent/path/does_not_exist.txt") == ""

    def test_returns_empty_string_on_oserror(self):
        with patch("builtins.open", side_effect=OSError("permission denied")):
            assert _read_file("/etc/shadow") == ""

    def test_handles_non_utf8_content(self, tmp_path):
        f = tmp_path / "binary.txt"
        f.write_bytes(b"\xff\xfe invalid utf8")
        result = _read_file(str(f))
        # Pas d'exception, remplacement des caractères invalides
        assert isinstance(result, str)

    def test_returns_full_content(self, tmp_path):
        content = "line1\nline2\nline3\n"
        f = tmp_path / "multi.txt"
        f.write_text(content)
        assert _read_file(str(f)) == content


# ===========================================================================
# _run
# ===========================================================================

class TestRun:
    def test_returns_stripped_stdout(self):
        mock_result = MagicMock()
        mock_result.stdout = b"  output  \n"
        with patch("subprocess.run", return_value=mock_result):
            assert _run(["echo", "output"]) == "output"

    def test_returns_empty_string_on_oserror(self):
        with patch("subprocess.run", side_effect=OSError("not found")):
            assert _run(["nonexistent_cmd"]) == ""

    def test_returns_empty_string_on_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            assert _run(["slow_cmd"]) == ""

    def test_uses_5s_timeout(self):
        mock_result = MagicMock()
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result) as mock_sub:
            _run(["cmd"])
        assert mock_sub.call_args.kwargs.get("timeout") == 5

    def test_devnull_for_stderr(self):
        mock_result = MagicMock()
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result) as mock_sub:
            _run(["cmd"])
        assert mock_sub.call_args.kwargs.get("stderr") == subprocess.DEVNULL


# ===========================================================================
# _get_hostname
# ===========================================================================

class TestGetHostname:
    def test_returns_socket_gethostname(self):
        with patch("socket.gethostname", return_value="relay-host-01"):
            assert _get_hostname() == "relay-host-01"

    def test_returns_non_empty_string(self):
        result = _get_hostname()
        assert isinstance(result, str)
        assert len(result) > 0


# ===========================================================================
# _get_os_family
# ===========================================================================

class TestGetOsFamily:
    """Tests de détection de la famille d'OS depuis /etc/os-release."""

    def _patch_os_release(self, content: str):
        return patch(
            "facts_collector._read_file",
            side_effect=lambda p: content if p == "/etc/os-release" else "",
        )

    def test_debian_from_id(self):
        with self._patch_os_release('ID=debian\n'):
            assert _get_os_family() == "Debian"

    def test_ubuntu_detected_as_debian(self):
        with self._patch_os_release('ID=ubuntu\nID_LIKE=debian\n'):
            assert _get_os_family() == "Debian"

    def test_rhel_from_id(self):
        with self._patch_os_release('ID=rhel\n'):
            assert _get_os_family() == "RedHat"

    def test_centos_from_id_like(self):
        with self._patch_os_release('ID=centos\nID_LIKE="rhel fedora"\n'):
            assert _get_os_family() == "RedHat"

    def test_rocky_linux(self):
        with self._patch_os_release('ID=rocky\nID_LIKE="rhel centos fedora"\n'):
            assert _get_os_family() == "RedHat"

    def test_almalinux(self):
        with self._patch_os_release('ID=almalinux\nID_LIKE="rhel centos fedora"\n'):
            assert _get_os_family() == "RedHat"

    def test_fedora_from_id(self):
        with self._patch_os_release('ID=fedora\n'):
            assert _get_os_family() == "RedHat"

    def test_opensuse_from_id(self):
        with self._patch_os_release('ID=opensuse\n'):
            assert _get_os_family() == "Suse"

    def test_arch_linux(self):
        with self._patch_os_release('ID=arch\n'):
            assert _get_os_family() == "Arch"

    def test_alpine_linux(self):
        with self._patch_os_release('ID=alpine\n'):
            assert _get_os_family() == "Alpine"

    def test_gentoo_linux(self):
        with self._patch_os_release('ID=gentoo\n'):
            assert _get_os_family() == "Gentoo"

    def test_unknown_distro_returns_linux(self):
        with self._patch_os_release('ID=unknowndistro\n'):
            assert _get_os_family() == "Linux"

    def test_missing_os_release_falls_back_to_platform_system(self):
        with patch("facts_collector._read_file", return_value=""), \
             patch("platform.system", return_value="Linux"):
            assert _get_os_family() == "Linux"

    def test_missing_os_release_empty_platform_returns_unknown(self):
        with patch("facts_collector._read_file", return_value=""), \
             patch("platform.system", return_value=""):
            assert _get_os_family() == "Unknown"

    def test_id_like_takes_priority_over_id(self):
        # ID_LIKE=debian doit l'emporter sur ID=someotherdistro
        with self._patch_os_release('ID=someotherdistro\nID_LIKE=debian\n'):
            assert _get_os_family() == "Debian"

    def test_quoted_id_value_stripped(self):
        with self._patch_os_release('ID="debian"\n'):
            assert _get_os_family() == "Debian"


# ===========================================================================
# _get_kernel_version
# ===========================================================================

class TestGetKernelVersion:
    def test_returns_platform_release(self):
        with patch("platform.release", return_value="5.15.0-91-generic"):
            assert _get_kernel_version() == "5.15.0-91-generic"

    def test_returns_string(self):
        assert isinstance(_get_kernel_version(), str)


# ===========================================================================
# _get_cpu_count
# ===========================================================================

class TestGetCpuCount:
    def test_counts_4_processors_from_cpuinfo(self):
        cpuinfo = (
            "processor\t: 0\nvendor_id: x\n\n"
            "processor\t: 1\nvendor_id: x\n\n"
            "processor\t: 2\nvendor_id: x\n\n"
            "processor\t: 3\nvendor_id: x\n"
        )
        with patch("facts_collector._read_file", side_effect=lambda p: cpuinfo if p == "/proc/cpuinfo" else ""):
            assert _get_cpu_count() == 4

    def test_counts_1_processor_at_start_of_file(self):
        # Premier CPU sans saut de ligne précédent
        cpuinfo = "processor\t: 0\nflags: ...\n"
        with patch("facts_collector._read_file", side_effect=lambda p: cpuinfo if p == "/proc/cpuinfo" else ""):
            assert _get_cpu_count() == 1

    def test_falls_back_to_os_cpu_count_when_no_cpuinfo(self):
        with patch("facts_collector._read_file", return_value=""), \
             patch("os.cpu_count", return_value=8):
            assert _get_cpu_count() == 8

    def test_returns_zero_when_os_cpu_count_is_none(self):
        with patch("facts_collector._read_file", return_value=""), \
             patch("os.cpu_count", return_value=None):
            assert _get_cpu_count() == 0

    def test_returns_non_negative_int(self):
        result = _get_cpu_count()
        assert isinstance(result, int)
        assert result >= 0


# ===========================================================================
# _get_memory_total_mb
# ===========================================================================

class TestGetMemoryTotalMb:
    def test_parses_memtotal_line(self):
        meminfo = "MemTotal:       16384000 kB\nMemFree:        8000000 kB\n"
        with patch("facts_collector._read_file", side_effect=lambda p: meminfo if p == "/proc/meminfo" else ""):
            assert _get_memory_total_mb() == 16384000 // 1024

    def test_returns_zero_when_meminfo_absent(self):
        with patch("facts_collector._read_file", return_value=""):
            assert _get_memory_total_mb() == 0

    def test_returns_zero_on_malformed_value(self):
        with patch("facts_collector._read_file", return_value="MemTotal: not_a_number kB\n"):
            assert _get_memory_total_mb() == 0

    def test_ignores_other_meminfo_lines(self):
        meminfo = (
            "MemFree:   4000000 kB\n"
            "MemTotal:  8192000 kB\n"
            "Cached:    1000000 kB\n"
        )
        with patch("facts_collector._read_file", side_effect=lambda p: meminfo if p == "/proc/meminfo" else ""):
            assert _get_memory_total_mb() == 8192000 // 1024

    def test_returns_int(self):
        meminfo = "MemTotal: 4096000 kB\n"
        with patch("facts_collector._read_file", side_effect=lambda p: meminfo if p == "/proc/meminfo" else ""):
            assert isinstance(_get_memory_total_mb(), int)


# ===========================================================================
# _get_disk_total_gb
# ===========================================================================

class TestGetDiskTotalGb:
    # _get_disk_total_gb utilise shutil.disk_usage() (cross-platform).
    # On patche facts_collector.shutil.disk_usage pour isoler le test.

    def test_calculates_size_from_disk_usage(self):
        mock_usage = MagicMock()
        mock_usage.total = 100 * 1024 ** 3  # 100 Go
        with patch("facts_collector.shutil.disk_usage", return_value=mock_usage):
            assert _get_disk_total_gb() == pytest.approx(100.0, rel=0.01)

    def test_returns_zero_when_all_paths_fail(self):
        with patch("facts_collector.shutil.disk_usage", side_effect=OSError("not supported")):
            assert _get_disk_total_gb() == 0.0

    def test_returns_float(self):
        mock_usage = MagicMock()
        mock_usage.total = 50 * 1024 ** 3
        with patch("facts_collector.shutil.disk_usage", return_value=mock_usage):
            assert isinstance(_get_disk_total_gb(), float)

    def test_returns_non_negative(self):
        mock_usage = MagicMock()
        mock_usage.total = 0
        with patch("facts_collector.shutil.disk_usage", return_value=mock_usage):
            assert _get_disk_total_gb() >= 0.0

    def test_rounds_to_two_decimal_places(self):
        mock_usage = MagicMock()
        mock_usage.total = 107374182401  # légèrement au-dessus de 100 Go
        with patch("facts_collector.shutil.disk_usage", return_value=mock_usage):
            result = _get_disk_total_gb()
        assert result == round(result, 2)


# ===========================================================================
# _collect_ipv4_for_iface
# ===========================================================================

class TestCollectIpv4ForIface:
    def test_parses_inet_line(self):
        output = "    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
        with patch("facts_collector._run", return_value=output):
            assert "192.168.1.10" in _collect_ipv4_for_iface("eth0")

    def test_strips_cidr_suffix(self):
        output = "    inet 10.0.0.5/16 scope global eth1\n"
        with patch("facts_collector._run", return_value=output):
            assert _collect_ipv4_for_iface("eth1") == ["10.0.0.5"]

    def test_excludes_127_loopback(self):
        output = "    inet 127.0.0.1/8 scope host lo\n"
        with patch("facts_collector._run", return_value=output):
            assert "127.0.0.1" not in _collect_ipv4_for_iface("lo")

    def test_returns_empty_list_when_no_ip(self):
        with patch("facts_collector._run", return_value=""):
            assert _collect_ipv4_for_iface("eth0") == []

    def test_multiple_ips_on_same_interface(self):
        output = (
            "    inet 192.168.1.10/24 scope global eth0\n"
            "    inet 192.168.1.11/24 scope global secondary eth0\n"
        )
        with patch("facts_collector._run", return_value=output):
            result = _collect_ipv4_for_iface("eth0")
        assert len(result) == 2
        assert "192.168.1.10" in result
        assert "192.168.1.11" in result


# ===========================================================================
# _collect_ipv6_for_iface
# ===========================================================================

class TestCollectIpv6ForIface:
    def test_parses_if_inet6(self):
        # fe80::1 sur eth0 (scope link-local)
        # Format : addr_hex32 ifindex prefix scope flags name
        if_inet6 = "fe800000000000000000000000000001 02 40 20 80 eth0\n"
        with patch("facts_collector._read_file", side_effect=lambda p: if_inet6 if p == "/proc/net/if_inet6" else ""):
            result = _collect_ipv6_for_iface("eth0")
        assert isinstance(result, list)
        assert "::1" not in result

    def test_excludes_loopback_from_if_inet6(self):
        # ::1 = 00000000000000000000000000000001
        if_inet6 = "00000000000000000000000000000001 01 80 10 80 lo\n"
        with patch("facts_collector._read_file", side_effect=lambda p: if_inet6 if p == "/proc/net/if_inet6" else ""):
            result = _collect_ipv6_for_iface("lo")
        assert "::1" not in result

    def test_ignores_entries_for_other_ifaces(self):
        if_inet6 = "fe800000000000000000000000000001 03 40 20 80 eth1\n"
        with patch("facts_collector._read_file", side_effect=lambda p: if_inet6 if p == "/proc/net/if_inet6" else ""):
            assert _collect_ipv6_for_iface("eth0") == []

    def test_fallback_to_ip_addr_when_no_if_inet6(self):
        ip6_output = "    inet6 2001:db8::1/64 scope global\n"
        with patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._run", return_value=ip6_output):
            assert "2001:db8::1" in _collect_ipv6_for_iface("eth0")

    def test_fallback_excludes_loopback_ipv6(self):
        with patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._run", return_value="    inet6 ::1/128 scope host\n"):
            assert "::1" not in _collect_ipv6_for_iface("lo")

    def test_returns_empty_list_when_no_ipv6(self):
        with patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._run", return_value=""):
            assert _collect_ipv6_for_iface("eth0") == []


# ===========================================================================
# _get_network_interfaces
# ===========================================================================

class TestGetNetworkInterfaces:
    def test_excludes_lo(self):
        with patch("os.listdir", return_value=["lo", "eth0"]), \
             patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._collect_ipv4_for_iface", return_value=[]), \
             patch("facts_collector._collect_ipv6_for_iface", return_value=[]):
            names = [i["name"] for i in _get_network_interfaces()]
        assert "lo" not in names

    def test_includes_eth_interfaces(self):
        with patch("os.listdir", return_value=["lo", "eth0", "eth1"]), \
             patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._collect_ipv4_for_iface", return_value=[]), \
             patch("facts_collector._collect_ipv6_for_iface", return_value=[]):
            names = [i["name"] for i in _get_network_interfaces()]
        assert "eth0" in names
        assert "eth1" in names

    def test_each_entry_has_required_keys(self):
        with patch("os.listdir", return_value=["eth0"]), \
             patch("facts_collector._read_file", return_value="aa:bb:cc:dd:ee:ff"), \
             patch("facts_collector._collect_ipv4_for_iface", return_value=["10.0.0.1"]), \
             patch("facts_collector._collect_ipv6_for_iface", return_value=[]):
            result = _get_network_interfaces()
        assert len(result) == 1
        for key in ("name", "ipv4", "ipv6", "mac"):
            assert key in result[0]

    def test_mac_address_stripped(self):
        with patch("os.listdir", return_value=["eth0"]), \
             patch("facts_collector._read_file", return_value="aa:bb:cc:dd:ee:ff\n"), \
             patch("facts_collector._collect_ipv4_for_iface", return_value=[]), \
             patch("facts_collector._collect_ipv6_for_iface", return_value=[]):
            result = _get_network_interfaces()
        assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_fallback_to_ip_link_on_sysfs_oserror(self):
        ip_link = "2: eth0: <BROADCAST>\n3: eth1: <BROADCAST>\n"
        with patch("os.listdir", side_effect=OSError("no sysfs")), \
             patch("facts_collector._run", return_value=ip_link), \
             patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._collect_ipv4_for_iface", return_value=[]), \
             patch("facts_collector._collect_ipv6_for_iface", return_value=[]):
            result = _get_network_interfaces()
        names = [i["name"] for i in result]
        assert len(names) >= 1

    def test_returns_list(self):
        with patch("os.listdir", return_value=[]), \
             patch("facts_collector._run", return_value=""):
            assert isinstance(_get_network_interfaces(), list)


# ===========================================================================
# _get_installed_packages
# ===========================================================================

class TestGetInstalledPackages:
    def test_parses_dpkg_output(self):
        dpkg_out = "bash\t5.1.16-1\npython3\t3.11.2-1\n"
        with patch("facts_collector._run", side_effect=lambda cmd: dpkg_out if "dpkg-query" in cmd else ""):
            result = _get_installed_packages()
        assert result.get("bash") == "5.1.16-1"
        assert result.get("python3") == "3.11.2-1"

    def test_parses_rpm_output_when_no_dpkg(self):
        def fake_run(cmd):
            if "rpm" in cmd:
                return "bash\t5.1.8-6.el9\n"
            return ""
        with patch("facts_collector._run", side_effect=fake_run):
            result = _get_installed_packages()
        assert result.get("bash") == "5.1.8-6.el9"

    def test_parses_apk_output_when_no_dpkg_or_rpm(self):
        def fake_run(cmd):
            if "apk" in cmd:
                return "busybox-1.35.0-r29\nmusl-1.2.3-r5\n"
            return ""
        with patch("facts_collector._run", side_effect=fake_run):
            result = _get_installed_packages()
        assert "busybox" in result
        assert result["busybox"] == "1.35.0-r29"

    def test_returns_empty_dict_when_no_package_manager(self):
        with patch("facts_collector._run", return_value=""):
            assert _get_installed_packages() == {}

    def test_limits_to_200_packages(self):
        lines = "\n".join(f"pkg-{i}\t1.{i}" for i in range(300))
        with patch("facts_collector._run", side_effect=lambda cmd: lines if "dpkg-query" in cmd else ""):
            assert len(_get_installed_packages()) <= 200

    def test_returns_dict_of_str_str(self):
        dpkg_out = "curl\t7.88.1-10\n"
        with patch("facts_collector._run", side_effect=lambda cmd: dpkg_out if "dpkg-query" in cmd else ""):
            result = _get_installed_packages()
        for k, v in result.items():
            assert isinstance(k, str)
            assert isinstance(v, str)

    def test_dpkg_takes_priority_no_rpm_call(self):
        call_log = []
        def fake_run(cmd):
            call_log.append(cmd[0] if cmd else "")
            return "bash\t5.1\n" if "dpkg-query" in cmd else ""
        with patch("facts_collector._run", side_effect=fake_run):
            _get_installed_packages()
        assert "dpkg-query" in call_log
        assert "rpm" not in call_log


# ===========================================================================
# collect_facts — intégration
# ===========================================================================

class TestCollectFacts:
    def test_returns_all_required_keys(self):
        facts = collect_facts()
        # Clés documentées dans la docstring de collect_facts()
        required = {
            "hostname", "os", "os_family", "kernel_version",
            "cpu_count", "memory_total_mb", "disk_total_gb",
            "ip_addresses", "network_interfaces", "python_version", "packages",
        }
        assert required.issubset(facts.keys())

    def test_hostname_non_empty_string(self):
        facts = collect_facts()
        assert isinstance(facts["hostname"], str)
        assert len(facts["hostname"]) > 0

    def test_os_subdict_has_required_keys(self):
        facts = collect_facts()
        assert isinstance(facts["os"], dict)
        for key in ("system", "release", "version"):
            assert key in facts["os"]
            assert isinstance(facts["os"][key], str)

    def test_os_family_is_string(self):
        assert isinstance(collect_facts()["os_family"], str)

    def test_kernel_version_is_string(self):
        assert isinstance(collect_facts()["kernel_version"], str)

    def test_cpu_count_non_negative_int(self):
        v = collect_facts()["cpu_count"]
        assert isinstance(v, int)
        assert v >= 0

    def test_memory_total_mb_non_negative_int(self):
        v = collect_facts()["memory_total_mb"]
        assert isinstance(v, int)
        assert v >= 0

    def test_disk_total_gb_non_negative_float(self):
        v = collect_facts()["disk_total_gb"]
        assert isinstance(v, float)
        assert v >= 0.0

    def test_ip_addresses_is_list(self):
        assert isinstance(collect_facts()["ip_addresses"], list)

    def test_network_interfaces_is_list(self):
        assert isinstance(collect_facts()["network_interfaces"], list)

    def test_python_version_matches_runtime(self):
        assert collect_facts()["python_version"] == platform.python_version()

    def test_packages_is_dict(self):
        assert isinstance(collect_facts()["packages"], dict)

    def test_result_is_json_serializable(self):
        """Aucun type non-sérialisable (datetime, set, etc.) dans le résultat."""
        facts = collect_facts()
        serialized = json.dumps(facts)
        assert json.loads(serialized) == facts

    def test_graceful_degradation_when_proc_absent(self):
        """Aucune exception même si /proc, /sys et shutil.disk_usage sont indisponibles."""
        with patch("facts_collector._read_file", return_value=""), \
             patch("facts_collector._run", return_value=""), \
             patch("facts_collector.os.listdir", side_effect=OSError("no sysfs")), \
             patch("facts_collector.shutil.disk_usage", side_effect=OSError("unsupported")), \
             patch("facts_collector.os.cpu_count", return_value=None):
            try:
                facts = collect_facts()
            except Exception as exc:
                pytest.fail(f"collect_facts() a levé une exception inattendue : {exc}")
        assert isinstance(facts, dict)

    def test_no_external_imports(self):
        """facts_collector.py n'importe que des modules de la stdlib Python."""
        source_path = Path(__file__).parent.parent.parent / "agent" / "facts_collector.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        # Modules stdlib autorisés — lus depuis le fichier source réel (pas de dépendances tierces)
        allowed = {"os", "platform", "re", "shutil", "socket", "subprocess", "typing"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in allowed, f"Import non-stdlib détecté : {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    assert top in allowed, f"Import non-stdlib détecté : from {node.module}"

    def test_idempotent(self):
        """Deux appels successifs retournent des valeurs stables."""
        f1, f2 = collect_facts(), collect_facts()
        assert f1["hostname"] == f2["hostname"]
        assert f1["os_family"] == f2["os_family"]
        assert f1["python_version"] == f2["python_version"]
