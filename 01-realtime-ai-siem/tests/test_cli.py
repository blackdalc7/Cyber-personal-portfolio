"""Run the real CLI as a subprocess: the exact path an operator uses."""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from helpers import FIXTURES

SRC = str(Path(__file__).resolve().parents[1] / "src")


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_cli_receives_replay_and_shuts_down_cleanly(tmp_path):
    port = free_udp_port()
    env = {**os.environ, "PYTHONPATH": SRC, "SIEM_OUTPUT_DIR": str(tmp_path), "LLM_PROVIDER": "offline",
           "SIEM_STATS_INTERVAL_S": "0"}
    env.pop("ANTHROPIC_API_KEY", None)
    proc = subprocess.Popen([sys.executable, "-m", "realtime_siem", "--host", "127.0.0.1", "--port", str(port)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 15
        while not (tmp_path / "siem.log").exists() or "Listening" not in (tmp_path / "siem.log").read_text():
            assert proc.poll() is None, proc.stdout.read()
            assert time.time() < deadline, "server did not start"
            time.sleep(0.05)
        replay = subprocess.run([sys.executable, "-m", "realtime_siem.replay", str(FIXTURES / "auth.log"),
                                 "--port", str(port), "--rate", "2000"],
                                env=env, capture_output=True, text=True, timeout=30)
        assert replay.returncode == 0 and "sent 138" in replay.stdout
        time.sleep(0.5)
    finally:
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=20)
    assert proc.returncode == 0, out
    assert "Final stats" in out
    alerts = [json.loads(x) for x in (tmp_path / "alerts.ndjson").read_text().splitlines()]
    assert {"SIEM-AUTH-002", "SIEM-PRIV-001"} <= {a["rule"]["id"] for a in alerts}
    assert (tmp_path / "chains.ndjson").exists()


def test_cli_rejects_bad_config(tmp_path):
    env = {**os.environ, "PYTHONPATH": SRC, "SYSLOG_BIND_PORT": "not-a-port"}
    res = subprocess.run([sys.executable, "-m", "realtime_siem", "--env-file", str(tmp_path / "none")],
                         env=env, capture_output=True, text=True, timeout=30)
    assert res.returncode == 2 and "configuration error" in res.stderr
