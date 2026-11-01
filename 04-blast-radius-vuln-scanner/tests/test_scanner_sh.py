"""scripts/scanner.sh, driven with a stub nmap so no real scanning happens."""

import os
import shutil
import subprocess
import sys

import pytest
from conftest import EXAMPLES, ROOT

SCRIPT = ROOT / "scripts" / "scanner.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


@pytest.fixture
def stub_path(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nmap = bin_dir / "nmap"
    # Records its argv and writes the lab scan wherever -oX points.
    nmap.write_text(f"""#!/usr/bin/env bash
if [[ "$1" == "--version" ]]; then echo "Nmap version 7.95 (stub)"; exit 0; fi
echo "$@" > "{tmp_path}/nmap_args"
while [[ $# -gt 0 ]]; do
  case "$1" in -oX) cp "{EXAMPLES / 'lab_scan.xml'}" "$2"; shift 2;; -oN) : > "$2"; shift 2;; *) shift;; esac
done
""")
    nmap.chmod(0o755)
    return bin_dir


def run(args, stub_path, tmp_path, authorized=True):
    env = {"PATH": f"{stub_path}:{os.environ['PATH']}", "PYTHON": sys.executable, "HOME": str(tmp_path)}
    if authorized:
        env["SCAN_AUTHORIZED"] = "yes"
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=tmp_path,
                          stdin=subprocess.DEVNULL, timeout=180, check=False)


def test_refuses_without_authorisation(stub_path, tmp_path):
    proc = run(["-t", "10.10.0.0/16"], stub_path, tmp_path, authorized=False)
    assert proc.returncode == 1 and "Authorisation" not in proc.stdout
    assert "SCAN_AUTHORIZED" in proc.stderr
    assert not (tmp_path / "nmap_args").exists()


@pytest.mark.parametrize("bad", [["-t", "10.0.0.1;id"], ["-t", "10.0.0.1", "-p", "80;id"],
                                 ["-t", "10.0.0.1", "--timing", "-T9"], ["--bogus"]])
def test_rejects_unsafe_arguments(stub_path, tmp_path, bad):
    proc = run(bad, stub_path, tmp_path)
    assert proc.returncode == 1
    assert not (tmp_path / "nmap_args").exists()


def test_full_pipeline_with_stub_nmap(stub_path, tmp_path):
    proc = run(["-t", "10.10.0.0/16", "-p", "1-10000", "-o", str(tmp_path / "out"), "-i",
                str(EXAMPLES / "inventory.yml"), "--feeds-dir", str(EXAMPLES / "feeds")], stub_path, tmp_path)
    assert proc.returncode == 0, proc.stderr
    args = (tmp_path / "nmap_args").read_text()
    assert "-sV" in args and "-p 1-10000" in args and ("-sT" in args or "-sS" in args)
    report = proc.stdout.strip().splitlines()[-1]
    assert report.endswith("_report.md") and os.path.exists(report)
    produced = sorted(p.name.split("_", 3)[-1] for p in (tmp_path / "out").iterdir())
    assert any(n.endswith(".sarif") for n in produced) and any(n.endswith("blast_radius.png") for n in produced)


def test_skip_cve_prints_xml_path(stub_path, tmp_path):
    proc = run(["-t", "10.10.1.10", "--skip-cve", "-o", str(tmp_path / "o")], stub_path, tmp_path)
    assert proc.returncode == 0 and proc.stdout.strip().endswith(".xml")
