from helpers import SCENARIOS, auth_event, finding
from watchfloor import ocsf
from watchfloor.scenarios import (
    DETECTED,
    MISSED,
    TELEMETRY_ONLY,
    Stage,
    list_scenarios,
    load_scenario,
    rebase,
    replay,
    score_stages,
    technique_matches,
)


def test_recorded_datasets_satisfy_the_contract():
    scenarios = list_scenarios(SCENARIOS)
    assert {s.id for s in scenarios} == {"ssh-bruteforce-to-persistence", "maldoc-to-ransomware"}
    for sc in scenarios:
        events = sc.events()
        assert events == sorted(events, key=lambda e: e["time"])
        for e in events:
            ocsf.validate(e)
            assert f"scenario:{sc.id}" in e["metadata"]["labels"]
        assert sc.simulated_parts, "every dataset must declare what was simulated"
        assert any(e["class_uid"] == ocsf.INCIDENT_FINDING for e in events)


def test_recorded_scores_show_real_gaps():
    """The datasets are honest: each has exactly one stage its source project cannot detect."""
    for sc in list_scenarios(SCENARIOS):
        results = score_stages(sc.stages, sc.events())
        outcomes = {r["stage"]: r["outcome"] for r in results}
        gaps = [k for k, v in outcomes.items() if v != DETECTED]
        assert gaps == {"ssh-bruteforce-to-persistence": ["shadow-read"],
                        "maldoc-to-ransomware": ["masquerading"]}[sc.id]
        assert all(outcomes[g] == TELEMETRY_ONLY for g in gaps)


def test_technique_matching():
    assert technique_matches("T1110", "T1110.001")
    assert technique_matches("T1110.001", "T1110")
    assert technique_matches("t1078", "T1078")
    assert not technique_matches("T1110.001", "T1110.003")


def test_score_stage_outcomes_and_ttd():
    t = 1793005200000
    stages = [Stage("a", "A", "x", ["T1110.001"], t + 1000, host="web01"),
              Stage("b", "B", "x", ["T1078"], t + 5000, host="web01"),
              Stage("c", "C", "x", ["T1486"], t + 9_000_000, host="db01")]
    events = [auth_event(t + 1500, False), finding(t + 4000, ["T1110"]), auth_event(t + 5200, True)]
    res = {r["stage"]: r for r in score_stages(stages, events)}
    assert res["a"]["outcome"] == DETECTED and res["a"]["ttd_ms"] == 3000
    assert res["b"]["outcome"] == TELEMETRY_ONLY and res["b"]["telemetry_events"] == 1
    assert res["c"]["outcome"] == MISSED and res["c"]["ttd_ms"] is None


def test_rebase_and_replay():
    sc = load_scenario(SCENARIOS / "maldoc-to-ransomware")
    events = sc.events()
    shifted, shift = rebase(events, events[0]["time"] + 1000)
    assert shift == 1000 and shifted[0]["metadata"]["uid"].endswith(f"@{events[0]['time'] + 1000}")
    assert rebase([], 5) == ([], 0)
    published, sleeps = [], []
    n = replay(sc, published.append, speed=10, sleep=sleeps.append, clock=lambda: 2_000_000_000)
    assert n == len(events) == len(published)
    assert published[0]["time"] == 2_000_000_000_000
    assert sleeps and max(sleeps) <= 5.0
    assert replay(sc, [].append, rebase_to_now=False, speed=0, sleep=sleeps.append) == len(events)


def test_list_scenarios_missing_dir(tmp_path):
    assert list_scenarios(tmp_path / "nope") == []
    assert load_scenario(SCENARIOS / "ssh-bruteforce-to-persistence").to_dict()["hosts"] == ["web01"]
