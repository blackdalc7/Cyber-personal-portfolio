import json

import fakeredis
import pytest

from helpers import PORTFOLIO, SCENARIOS
from watchfloor import cli
from watchfloor.bus import EventBus
from watchfloor.config import ConfigError, Settings


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WF_LAKE_DIR", str(tmp_path / "lake"))
    monkeypatch.setenv("WF_SCENARIOS_DIR", str(SCENARIOS))
    for k in ("WF_SIEM_DIR", "WF_EDR_ALERTS", "WF_TRIAGE_QUEUE", "WF_SOAR_URL"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


@pytest.fixture
def fake_bus(monkeypatch):
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    monkeypatch.setattr(cli, "_bus", lambda settings: bus)
    return bus


def test_settings_from_env_and_errors():
    s = Settings.from_env({"WF_FLUSH_ROWS": "10", "WF_CORS_ORIGINS": "a, b", "WF_SOAR_URL": "http://x/"})
    assert s.flush_rows == 10 and s.cors_origins == ("a", "b") and s.soar_url == "http://x"
    with pytest.raises(ConfigError):
        Settings.from_env({"WF_FLUSH_ROWS": "x"})
    with pytest.raises(ConfigError):
        Settings.from_env({"WF_FLUSH_ROWS": "0"})


def test_load_and_validate(env, capsys):
    assert cli.main(["load", "all"]) == 0
    assert "Loaded 200 events from 2" in capsys.readouterr().out
    assert cli.main(["load", "maldoc-to-ransomware"]) == 0
    good = SCENARIOS / "maldoc-to-ransomware" / "events.ndjson"
    assert cli.main(["validate", str(good)]) == 0
    bad = env / "bad.ndjson"
    bad.write_text('{"class_uid": 1}\n\nnot json\n')
    assert cli.main(["validate", str(bad)]) == 1
    assert cli.main(["compact", "--older-than", "0"]) == 0


def test_replay_publishes(env, fake_bus):
    assert cli.main(["replay", "maldoc-to-ransomware", "--speed", "0"]) == 0
    assert fake_bus.r.xlen("wf:events") == 50


def test_adapters_once(env, fake_bus, monkeypatch, tmp_path):
    assert cli.main(["adapters", "--once"]) == 2
    monkeypatch.setenv("WF_TRIAGE_QUEUE", str(PORTFOLIO / "06-alert-clustering-fp-reducer/examples/output/queue.json"))
    monkeypatch.setenv("WF_EDR_ALERTS", str(tmp_path / "none.ndjson"))
    monkeypatch.setenv("WF_SIEM_DIR", str(tmp_path))
    assert cli.main(["adapters", "--once"]) == 0
    assert fake_bus.r.xlen("wf:events") > 10


def test_export_demo(env, monkeypatch, capsys):
    expo = PORTFOLIO / "04-blast-radius-vuln-scanner/examples/output/findings.json"
    monkeypatch.setenv("WF_EXPOSURE_FILE", str(expo))
    monkeypatch.setenv("WF_COVERAGE_DIR", str(PORTFOLIO / "05-sigma-attack-coverage/examples/output"))
    monkeypatch.setenv("WF_TRIAGE_QUEUE", str(PORTFOLIO / "06-alert-clustering-fp-reducer/examples/output/queue.json"))
    out = env / "demo"
    assert cli.main(["export-demo", "--out", str(out)]) == 0
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["has_exposure"] and manifest["has_triage"] and len(manifest["incidents"]) == 2
    for inc in manifest["incidents"]:
        assert (out / "incident" / f"{inc}.json").is_file()
    assert (out / "score" / "maldoc-to-ransomware.json").is_file()
    assert json.loads((out / "coverage.json").read_text())[0]["kind"] == "exercise"
    assert cli.main(["export-demo", "--out", str(out)]) == 0  # overwrites cleanly


def test_ingest_command_stops_on_interrupt(env, fake_bus, monkeypatch):
    from watchfloor import ingest

    def boom(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(ingest.IngestService, "run", boom)
    assert cli.main(["ingest"]) == 0


def test_hub_command_without_redis(env, monkeypatch):
    import uvicorn

    calls = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw))

    def no_redis(settings):
        raise ConnectionError("down")

    monkeypatch.setattr(cli, "_bus", no_redis)
    assert cli.main(["hub", "--port", "8123"]) == 0
    assert calls["port"] == 8123
