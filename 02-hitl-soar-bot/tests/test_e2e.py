"""Real HTTP server + the operator scripts: alert -> card -> signed click -> isolation."""

import json
import os
import socket
import subprocess
import sys
import threading
import time

from helpers import APPROVER, ROOT, SAMPLES, SLACK_SECRET, WEBHOOK_SECRET
from waitress import create_server

from soar_bot.app import create_app
from soar_bot.config import Settings
from soar_bot.server import build_service


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_full_loop_over_http(tmp_path):
    port = free_port()
    env = {"WEBHOOK_SHARED_SECRET": WEBHOOK_SECRET, "SLACK_SIGNING_SECRET": SLACK_SECRET,
           "SLACK_APPROVER_IDS": APPROVER, "SOAR_DATA_DIR": str(tmp_path), "LISTEN_PORT": str(port),
           "SOAR_API_TOKEN": "a" * 32}
    settings = Settings.from_env(env)
    service = build_service(settings)
    server = create_server(create_app(settings, service), host="127.0.0.1", port=port)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    child_env = {**os.environ, **env, "SOAR_URL": f"http://127.0.0.1:{port}"}
    try:
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "simulate_alert.py"),
                              str(SAMPLES / "ssh_bruteforce.json")], env=child_env, capture_output=True,
                             text=True, timeout=30, cwd=tmp_path)
        assert out.returncode == 0, out.stdout + out.stderr
        incident_id = json.loads(out.stdout.split(" ", 1)[1])["incident_id"]
        assert not (tmp_path / "isolation_state.json").exists()

        click = subprocess.run([sys.executable, str(ROOT / "scripts" / "simulate_click.py"), incident_id,
                                "--user", APPROVER, "--outbox", str(tmp_path / "outbox")],
                               env=child_env, capture_output=True, text=True, timeout=30, cwd=tmp_path)
        assert click.returncode == 0, click.stdout + click.stderr
        for _ in range(100):
            if service.db.get(incident_id).status == "remediated":
                break
            time.sleep(0.05)
        assert service.db.get(incident_id).status == "remediated"
        state = json.loads((tmp_path / "isolation_state.json").read_text())
        assert "web01" in state["isolated_hosts"]
        assert len(list((tmp_path / "outbox").glob(f"{incident_id}-*-update.json"))) == 3
    finally:
        server.close()
        service.shutdown()
