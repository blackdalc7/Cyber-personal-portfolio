"""Tests for the CLI subcommands, exit codes and settings."""

import json
import subprocess
import sys

import pytest
import responses
from conftest import EXAMPLES, ROOT

from vuln_scanner.cli import main
from vuln_scanner.config import ConfigError, Settings


def args(tmp_path, *extra):
    return [
        "analyse",
        str(EXAMPLES / "lab_scan.xml"),
        "--inventory",
        str(EXAMPLES / "inventory.yml"),
        "--feeds-dir",
        str(EXAMPLES / "feeds"),
        "--env-file",
        str(tmp_path / "none.env"),
        *extra,
    ]


def test_analyse_writes_every_output(tmp_path, capsys):
    out = tmp_path / "out"
    rc = main(
        args(
            tmp_path,
            "--sarif",
            str(out / "r.sarif"),
            "--json",
            str(out / "f.json"),
            "--report",
            str(out / "report.md"),
            "--graph",
            str(out / "img" / "blast.png"),
            "--graph-json",
            str(out / "g.json"),
        )
    )
    assert rc == 0
    assert json.loads((out / "r.sarif").read_text())["version"] == "2.1.0"
    assert json.loads((out / "f.json").read_text())["entry_points"] == ["10.10.1.10"]
    assert "![Blast radius](img/blast.png)" in (out / "report.md").read_text()
    assert (out / "img" / "blast.png").exists() and (out / "g.json").exists()
    assert "11 findings across 9 hosts" in capsys.readouterr().out


def test_fail_on_gate(tmp_path):
    assert main(args(tmp_path, "--fail-on", "50")) == 2
    assert main(args(tmp_path, "--fail-on", "99")) == 0


def test_errors_exit_1(tmp_path):
    bad = tmp_path / "inv.yml"
    bad.write_text("assets:\n - {ip: nope}\n")
    assert (
        main(
            [
                "analyse",
                str(EXAMPLES / "lab_scan.xml"),
                "--inventory",
                str(bad),
                "--feeds-dir",
                str(EXAMPLES / "feeds"),
                "--env-file",
                str(tmp_path / "x"),
            ]
        )
        == 1
    )
    assert main(["analyse", str(tmp_path / "missing.xml"), "--env-file", str(tmp_path / "x")]) == 1


def test_offline_without_cache_reports_incomplete_data(tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_CACHE_PATH", str(tmp_path / "cache.sqlite"))
    rc = main(
        [
            "analyse",
            str(EXAMPLES / "lab_scan.xml"),
            "--offline",
            "--json",
            str(tmp_path / "f.json"),
            "--env-file",
            str(tmp_path / "none.env"),
        ]
    )
    assert rc == 0
    doc = json.loads((tmp_path / "f.json").read_text())
    assert doc["findings"] == [] and any("offline" in e for e in doc["errors"])


@responses.activate
def test_snapshot_records_live_feeds_for_reuse(tmp_path, monkeypatch):
    s = Settings.from_env({})
    nvd = json.loads((EXAMPLES / "feeds" / "nvd.json").read_text())
    epss = json.loads((EXAMPLES / "feeds" / "epss.json").read_text())

    def nvd_cb(request):
        from urllib.parse import parse_qs, urlparse

        cpe = parse_qs(urlparse(request.url).query)["virtualMatchString"][0]
        return 200, {}, json.dumps(nvd.get(cpe, {"totalResults": 0, "vulnerabilities": []}))

    responses.add_callback(responses.GET, s.nvd_url, callback=nvd_cb)
    responses.get(s.epss_url, json=epss)
    responses.get(s.kev_url, body=(EXAMPLES / "feeds" / "kev.json").read_text())
    monkeypatch.setenv("VULN_CACHE_PATH", str(tmp_path / "cache.sqlite"))
    monkeypatch.setenv("NVD_API_KEY", "test-key-not-real")  # 0.65 s spacing keeps the test quick
    feeds = tmp_path / "feeds"
    assert (
        main(["snapshot", str(EXAMPLES / "lab_scan.xml"), "--out", str(feeds), "--env-file", str(tmp_path / "x")]) == 0
    )
    assert all(
        c.request.headers.get("apiKey") == "test-key-not-real" for c in responses.calls if "nvd" in c.request.url
    )
    # The snapshot must reproduce the same analysis offline.
    out = tmp_path / "f.json"
    assert (
        main(
            [
                "analyse",
                str(EXAMPLES / "lab_scan.xml"),
                "--inventory",
                str(EXAMPLES / "inventory.yml"),
                "--feeds-dir",
                str(feeds),
                "--json",
                str(out),
                "--env-file",
                str(tmp_path / "x"),
            ]
        )
        == 0
    )
    assert json.loads(out.read_text())["findings"][0]["cve"] == "CVE-2021-42013"


def test_settings_from_env():
    s = Settings.from_env({"NVD_API_KEY": "abc", "VULN_MAX_HOPS": "3", "VULN_OFFLINE": "yes", "VULN_KEV_FLOOR": "0.9"})
    assert (s.max_hops, s.offline, s.kev_likelihood_floor, s.nvd_delay_s) == (3, True, 0.9, 0.65)
    assert "abc" not in repr(s)
    assert Settings.from_env({}).nvd_delay_s == 6.5


@pytest.mark.parametrize(
    ("env", "msg"),
    [
        ({"VULN_MAX_HOPS": "0"}, "between"),
        ({"VULN_MAX_HOPS": "2.5"}, "integer"),
        ({"VULN_KEV_FLOOR": "x"}, "number"),
        ({"VULN_OFFLINE": "maybe"}, "boolean"),
    ],
)
def test_settings_validation(env, msg):
    with pytest.raises(ConfigError, match=msg):
        Settings.from_env(env)


def test_module_entry_point(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "vuln_scanner",
            "analyse",
            str(EXAMPLES / "lab_scan.xml"),
            "--inventory",
            str(EXAMPLES / "inventory.yml"),
            "--feeds-dir",
            str(EXAMPLES / "feeds"),
            "--env-file",
            str(tmp_path / "x"),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "CVE-2021-42013" in proc.stdout
