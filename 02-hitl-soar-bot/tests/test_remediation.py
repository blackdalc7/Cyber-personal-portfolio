"""Tests for the isolation subprocess: success, dry run, injection, timeouts and environment."""

import json
import sys

from soar_bot.remediation import Remediator

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))
import mock_isolate


def test_isolate_success(settings, tmp_path):
    r = Remediator(settings.remediation_script, tmp_path / "s.json").isolate("INC-20261026-ABCDEF12", "web01",
                                                                            "203.0.113.5")
    assert r.ok and r.exit_code == 0 and r.output["host"] == "web01"
    assert "nft add rule inet filter input ip saddr 203.0.113.5 drop" in r.output["rules"]


def test_dry_run_writes_nothing(settings, tmp_path):
    r = Remediator(settings.remediation_script, tmp_path / "s.json", dry_run=True).isolate(
        "INC-20261026-ABCDEF12", "web01", None)
    assert r.ok and r.output["dry_run"] is True and not (tmp_path / "s.json").exists()


def test_rejects_injection_before_spawning(settings, tmp_path):
    rem = Remediator(settings.remediation_script, tmp_path / "s.json")
    assert rem.isolate("INC-20261026-ABCDEF12", "web01;reboot", None).exit_code == 2
    assert rem.isolate("INC-20261026-ABCDEF12", "web01", "1.2.3.4; id").exit_code == 2
    assert rem.isolate("INC-20261026-ABCDEF12", None, None).ok is False


def test_missing_script(tmp_path):
    assert Remediator(tmp_path / "nope.py", tmp_path / "s.json").isolate("INC-1", "h", None).exit_code == 127


def test_timeout(tmp_path):
    slow = tmp_path / "slow.py"
    slow.write_text("import time; time.sleep(5)")
    r = Remediator(slow, tmp_path / "s.json", timeout_s=1).isolate("INC-1", "h", None)
    assert not r.ok and "timed out" in r.output["error"]


def test_child_does_not_inherit_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-secret")
    probe = tmp_path / "probe.py"
    probe.write_text("import json, os; print(json.dumps({'ok': True, 'leak': os.getenv('SLACK_BOT_TOKEN')}))")
    r = Remediator(probe, tmp_path / "s.json").isolate("INC-1", "h", None)
    assert r.ok and r.output["leak"] is None


def test_script_validation_and_state(tmp_path, capsys):
    state = tmp_path / "state.json"
    assert mock_isolate.main(["--incident", "bad", "--host", "h", "--state-file", str(state)]) == 2
    assert mock_isolate.main(["--incident", "INC-20261026-ABCDEF12", "--host=-x", "--state-file",
                              str(state)]) == 2
    assert mock_isolate.main(["--incident", "INC-20261026-ABCDEF12", "--host", "h", "--ip", "nope",
                              "--state-file", str(state)]) == 2
    for host in ("a1", "b2"):
        assert mock_isolate.main(["--incident", "INC-20261026-ABCDEF12", "--host", host,
                                  "--state-file", str(state)]) == 0
    assert set(json.loads(state.read_text())["isolated_hosts"]) == {"a1", "b2"}
    state.write_text("{corrupt")
    assert mock_isolate.main(["--incident", "INC-20261026-ABCDEF12", "--host", "c3",
                              "--state-file", str(state)]) == 1
