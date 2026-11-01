from __future__ import annotations

import random

import httpx
import pytest

from attack_emulator.poller import HubClient, backoff_delays, technique_matches, wait_for_detection


@pytest.mark.parametrize("wanted, seen, ok", [
    ("T1059.001", "T1059.001", True), ("T1059.001", "T1059", True), ("T1059", "T1059.003", True),
    ("t1059", "T1059", True), ("T1059.001", "T1059.003", False), ("T1003", "T1059", False)])
def test_technique_matches(wanted, seen, ok):
    assert technique_matches(wanted, seen) is ok


def test_backoff_bounds():
    d = backoff_delays(2, 10, random.Random(1))
    for n in range(8):
        v = d(n)
        assert 1 <= v <= min(10, 2 * 2 ** n)


def hub_with(handler, token="t"):
    return HubClient("http://hub.test/", token, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_hub_client_filters():
    calls = []

    def handler(req: httpx.Request):
        calls.append(req)
        if req.url.path == "/api/findings":
            return httpx.Response(200, json=[
                {"time": 1, "techniques": ["T1059.001"], "hostname": "LAB-K8S"},
                {"time": 2, "techniques": ["T1059.003"], "hostname": "lab-k8s"},
                {"time": 3, "techniques": ["T1059.001"], "hostname": "other"}])
        if req.url.path == "/api/events":
            return httpx.Response(200, json=[{"class_uid": 1007}, {"class_uid": 2004}])
        if req.url.path == "/api/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"not": "a list"})

    hub = hub_with(handler)
    assert [f["time"] for f in hub.findings(0, "T1059.001", "lab-k8s")] == [1]
    assert calls[0].url.params["technique"] == "T1059" and calls[0].headers["Authorization"] == "Bearer t"
    assert hub.telemetry(0, 10, "lab-k8s", "shadow") == [{"class_uid": 1007}]
    assert calls[1].url.params["q"] == "shadow"
    assert hub.health() == {"status": "ok"}
    assert hub._get("/api/other", {}) == []
    hub.close()
    assert "Authorization" not in hub_with(handler, token="")._headers


class FakeHub:
    def __init__(self, findings_seq, telemetry=0, telemetry_error=False):
        self.seq, self.n_tel, self.tel_err, self.calls = list(findings_seq), telemetry, telemetry_error, 0

    def findings(self, since, technique, hostname):
        self.calls += 1
        item = self.seq.pop(0) if self.seq else []
        if isinstance(item, Exception):
            raise item
        return item

    def telemetry(self, since, until, hostname, match=None):
        if self.tel_err:
            raise httpx.ConnectError("down")
        return [{}] * self.n_tel


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run(hub, clock=None, timeout=30):
    clock = clock or Clock()
    return wait_for_detection(hub, technique="T1003.008", hostname="lab-k8s", start_ms=1_000_000, timeout_s=timeout,
                              base_s=1, max_s=4, window_s=900, clock=clock, sleep=clock.sleep, rng=random.Random(0))


def test_detected_after_a_few_polls():
    hit = {"time": 1_004_500, "finding_title": "shadow read", "product": "detection-rules", "uid": "f1"}
    early = {"time": 990_000}  # before the technique started: ignored
    obs = run(FakeHub([[], [early], [hit, {"time": 1_009_000}]], telemetry=3))
    assert obs.outcome == "detected" and obs.ttd_ms == 4500 and obs.polls == 3
    assert obs.findings[0]["title"] == "shadow read" and obs.telemetry_events == 3


def test_telemetry_only_and_missed():
    assert run(FakeHub([], telemetry=2)).outcome == "telemetry_only"
    obs = run(FakeHub([]))
    assert obs.outcome == "missed" and obs.polls > 3


def test_hub_down_is_error_not_miss():
    obs = run(FakeHub([httpx.ConnectError("x")] * 100, telemetry_error=True))
    assert obs.outcome == "error" and "ConnectError" in obs.errors


def test_partial_errors_still_scored():
    obs = run(FakeHub([httpx.ConnectError("x"), ValueError("bad json")], telemetry=1))
    assert obs.outcome == "telemetry_only" and obs.errors[:2] == ["ConnectError", "ValueError"]
