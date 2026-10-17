import importlib
import os

import pytest
from fastapi.testclient import TestClient

import app as eclipse


@pytest.fixture
def client(monkeypatch):
    """Use deterministic incident data and avoid connecting to live FalkorDB."""
    incident = {
        "incident_id": "INC-TEST-AUTO",
        "type": "simulated_security_event",
        "severity": "high",
        "current_status": "open",
        "evidence": [
            {
                "type": "suspicious_process",
                "confidence": 0.97,
                "source": "pytest",
                "host": "sandbox-host-01",
                "environment": "sandbox",
            }
        ],
        "proposed_action": "isolate_demo_host",
        "policy_decision": "approved_for_simulation",
    }

    monkeypatch.setattr(eclipse, "inspect_incident", lambda incident_id: dict(incident))
    monkeypatch.setattr(eclipse, "persist_agent_run", lambda **kwargs: True)
    monkeypatch.delenv("ECLIPSE_KILL_SWITCH", raising=False)
    eclipse._SIMULATED_HOST_STATE.clear()

    return TestClient(eclipse.app)


def test_normal_run_executes_and_verifies_simulation(client):
    response = client.post(
        "/agent/run",
        json={
            "incident_id": "INC-TEST-AUTO",
            "max_steps": 8,
            "simulate_verification_failure": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["agent_status"] == "simulation_verified"
    assert body["verified"] is True
    assert body["recovery_attempted"] is False
    assert body["memory_persisted"] is True
    assert [step["tool"] for step in body["steps"]] == [
        "inspect_incident",
        "safety_gate",
        "simulated_executor",
        "verify_simulation",
    ]
    action = body["steps"][2]["result"]
    assert action["simulated_state"] == "isolated"
    assert action["real_host_changed"] is False


def test_failed_verification_triggers_rollback_and_reverification(client):
    response = client.post(
        "/agent/run",
        json={
            "incident_id": "INC-TEST-AUTO",
            "max_steps": 8,
            "simulate_verification_failure": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["agent_status"] == "recovery_verified"
    assert body["verified"] is True
    assert body["recovery_attempted"] is True
    assert body["execution"] == "simulated_recovered"
    assert body["memory_persisted"] is True
    assert [step["tool"] for step in body["steps"]] == [
        "inspect_incident",
        "safety_gate",
        "simulated_executor",
        "verify_simulation",
        "diagnose_failure",
        "recovery",
        "verify_recovery",
    ]
    diagnosis = body["steps"][4]["result"]
    assert diagnosis["failure_detected"] is True
    assert diagnosis["recommended_response"] == "single_simulated_rollback"
    recovery = body["steps"][5]["result"]
    assert recovery["previous_simulated_state"] == "isolated"
    assert recovery["simulated_state"] == "restored"
    assert recovery["real_host_changed"] is False
    assert body["steps"][6]["result"]["recovery_verified"] is True


def test_kill_switch_blocks_before_simulated_execution(client, monkeypatch):
    monkeypatch.setenv("ECLIPSE_KILL_SWITCH", "true")

    response = client.post(
        "/agent/run",
        json={
            "incident_id": "INC-TEST-AUTO",
            "max_steps": 8,
            "simulate_verification_failure": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["agent_status"] == "blocked_pending_review"
    assert body["verified"] is False
    tools = [step["tool"] for step in body["steps"]]
    assert tools == ["inspect_incident", "safety_gate"]
    gate = body["steps"][1]
    assert gate["result"] == "blocked"
    assert "Emergency kill switch is enabled." in gate["reasons"]
    assert "simulated_executor" not in tools


def test_safety_gate_rejects_non_allowlisted_action(monkeypatch):
    monkeypatch.delenv("ECLIPSE_KILL_SWITCH", raising=False)
    incident = {
        "severity": "high",
        "evidence": [{"confidence": 0.99, "environment": "sandbox"}],
        "proposed_action": "delete_host",
    }

    allowed, reasons = eclipse.safety_gate(incident)

    assert allowed is False
    assert "Action is not allowlisted." in reasons


def test_invalid_request_is_rejected(client):
    response = client.post(
        "/agent/run",
        json={"incident_id": "INC-TEST-AUTO", "max_steps": 0},
    )

    assert response.status_code == 422


def test_planner_uses_observed_failure_and_historical_recovery():
    plan = eclipse.plan_next_tool(
        incident={"historical_memory": {"verified_recoveries": 1}},
        previous_result={"verified": False, "diagnosis": {"observed_simulated_state": "isolated"}},
        completed_tools=["inspect_incident", "safety_gate", "simulated_executor", "verify_simulation"],
    )
    assert plan["tool"] == "diagnose_failure"
    assert "isolated" in plan["reason"]
    assert "historical verified recoveries" in plan["reason"]
    assert "independent safety policy" in plan["reason"]


def test_graph_context_returns_related_incident_evidence(monkeypatch):
    class Result:
        result_set = [[
            "INC-A", "high",
            [{"host": "sandbox-1", "environment": "sandbox", "evidence_type": "suspicious_process", "confidence": 0.97, "source": "test"}],
            [{"incident_id": "INC-B", "severity": "medium", "status": "open", "shared_host": "sandbox-1", "evidence_type": "login_anomaly"}],
        ]]

    class FakeGraph:
        def query(self, query, params):
            return Result()

    monkeypatch.setattr(eclipse, "get_graph", lambda: FakeGraph())
    context = eclipse.get_related_graph_context("INC-A")
    assert context["graph_grounded"] is True
    assert context["related_incident_count"] == 1
    assert context["related_incidents"][0]["incident_id"] == "INC-B"


def test_monitor_cycle_persists_observation_without_execution(client, monkeypatch):
    monkeypatch.setattr(eclipse, "inspect_incident", lambda incident_id: {
        "incident_id": incident_id, "severity": "high", "current_status": "open",
        "evidence": [{"type": "suspicious_process", "confidence": 0.97,
                      "host": "sandbox-1", "environment": "sandbox", "source": "pytest"}],
        "policy_decision": "approved_for_simulation",
    })
    monkeypatch.setattr(eclipse, "get_related_graph_context", lambda incident_id: {
        "incident_id": incident_id, "severity": "high", "evidence_context": [],
        "related_incidents": [], "related_incident_count": 0, "graph_grounded": True,
    })
    monkeypatch.setattr(eclipse, "retrieve_agent_memory", lambda incident_id, limit=10: {
        "available": True, "records_considered": 2, "verified_recoveries": 1,
    })

    class QueryResult:
        def __init__(self, rows):
            self.result_set = rows

    class FakeGraph:
        def query(self, query, params):
            if "RETURN m.fingerprint" in query:
                return QueryResult([])
            return QueryResult([[params["cycle_id"]]])

    monkeypatch.setattr(eclipse, "get_graph", lambda: FakeGraph())
    response = client.post("/agent/monitor-cycle", json={"incident_id": "INC-TEST-AUTO"})
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "baseline_observed"
    assert body["execution_performed"] is False
    assert body["real_world_actions_enabled"] is False
    assert body["memory_summary"]["verified_recoveries"] == 1


def test_autonomy_status_is_simulation_only(client):
    response = client.get("/agent/autonomy/status")
    assert response.status_code == 200
    body = response.json()
    assert body["real_world_actions_enabled"] is False
    assert body["mode"] == "autonomous_simulation_only"


def test_autonomy_start_stop_lifecycle(client, monkeypatch):
    monkeypatch.setattr(eclipse, "inspect_incident", lambda incident_id: {
        "incident_id": incident_id, "severity": "high", "current_status": "open",
        "evidence": [], "policy_decision": "blocked",
    })
    monkeypatch.setattr(eclipse, "monitor_cycle", lambda request: {
        "cycle_id": "cycle-test", "incident_id": request.incident_id,
        "decision": "continue_monitoring", "change_detected": False,
        "observed_at": "test-time",
    })
    monkeypatch.setattr(eclipse, "run_agent", lambda request: {
        "run_id": "run-test", "incident_id": request.incident_id,
        "agent_status": "blocked_pending_review", "verified": False,
        "simulation_only": True, "completed_at": "test-time",
    })

    started = client.post("/agent/autonomy/start", json={
        "incident_ids": ["INC-TEST-AUTO"], "interval_seconds": 15, "max_steps": 8,
    })
    assert started.status_code == 200
    assert started.json()["running"] is True
    assert started.json()["real_world_actions_enabled"] is False

    stopped = client.post("/agent/autonomy/stop")
    assert stopped.status_code == 200
    assert stopped.json()["stopped"] is True
    assert stopped.json()["running"] is False


def test_autonomy_worker_runs_agent_on_baseline_then_honors_stop(monkeypatch):
    import asyncio

    calls = {"monitor": 0, "agent": 0}
    stop_event = asyncio.Event()

    def fake_monitor(request):
        calls["monitor"] += 1
        stop_event.set()
        return {
            "cycle_id": "cycle-baseline", "incident_id": request.incident_id,
            "decision": "baseline_observed", "change_detected": False,
            "observed_at": "test-time",
        }

    def fake_run(request):
        calls["agent"] += 1
        return {
            "run_id": "run-baseline", "agent_status": "blocked_pending_review",
            "verified": False, "simulation_only": True, "completed_at": "test-time",
        }

    monkeypatch.setattr(eclipse, "monitor_cycle", fake_monitor)
    monkeypatch.setattr(eclipse, "run_agent", fake_run)
    eclipse._AUTONOMY_STATUS.update({"cycles_completed": 0, "agent_runs_started": 0})

    asyncio.run(eclipse._autonomy_worker(["INC-TEST-AUTO"], 15, 8, stop_event))

    assert calls == {"monitor": 1, "agent": 1}
    assert eclipse._AUTONOMY_STATUS["cycles_completed"] == 1
    assert eclipse._AUTONOMY_STATUS["agent_runs_started"] == 1
    assert eclipse._AUTONOMY_STATUS["last_cycle"]["decision"] == "baseline_observed"
    assert eclipse._AUTONOMY_STATUS["last_agent_run"]["simulation_only"] is True


def test_unrecoverable_recovery_stops_safely(client, monkeypatch):
    import app as eclipse

    # Force only recovery verification to fail; no real system is touched.
    monkeypatch.setattr(eclipse, "verify_recovery", lambda recovery: False)

    response = client.post(
        "/agent/run",
        json={
            "incident_id": "INC-TEST-AUTO",
            "max_steps": 8,
            "simulate_verification_failure": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is False
    assert body["agent_status"] == "verification_failed"
    assert body["recovery_attempted"] is True
    assert body["execution"] != "simulated_success"
    assert body["steps"][-1]["tool"] == "verify_recovery"
    assert body["steps"][-1]["result"]["recovery_verified"] is False
    assert body["steps"][-1]["result"]["real_host_changed"] is False


def test_autonomy_worker_reruns_agent_on_material_change(monkeypatch):
    import asyncio

    calls = {"monitor": 0, "agent": 0}
    stop_event = asyncio.Event()

    def fake_monitor(request):
        calls["monitor"] += 1
        changed = calls["monitor"] == 2
        if changed:
            stop_event.set()
        return {
            "cycle_id": f"cycle-{calls['monitor']}",
            "incident_id": request.incident_id,
            "decision": "rerun_triage" if changed else "baseline_observed",
            "change_detected": changed,
            "observed_at": "test-time",
        }

    def fake_run(request):
        calls["agent"] += 1
        return {
            "run_id": f"run-{calls['agent']}",
            "incident_id": request.incident_id,
            "agent_status": "simulation_verified",
            "verified": True,
            "simulation_only": True,
            "completed_at": "test-time",
        }

    monkeypatch.setattr(eclipse, "monitor_cycle", fake_monitor)
    monkeypatch.setattr(eclipse, "run_agent", fake_run)
    eclipse._AUTONOMY_STATUS.update({
        "cycles_completed": 0,
        "agent_runs_started": 0,
        "last_cycle": None,
        "last_agent_run": None,
        "last_error": None,
    })

    asyncio.run(
        eclipse._autonomy_worker(
            ["INC-TEST-AUTO"], 15, 8, stop_event
        )
    )

    assert calls == {"monitor": 2, "agent": 2}
    assert eclipse._AUTONOMY_STATUS["cycles_completed"] == 2
    assert eclipse._AUTONOMY_STATUS["agent_runs_started"] == 2
    assert eclipse._AUTONOMY_STATUS["last_cycle"]["decision"] == "rerun_triage"
    assert eclipse._AUTONOMY_STATUS["last_cycle"]["change_detected"] is True
    assert eclipse._AUTONOMY_STATUS["last_agent_run"]["simulation_only"] is True
