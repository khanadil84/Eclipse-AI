
import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from falkordb import FalkorDB
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = FastAPI(
    title="Eclipse AI",
    description="Graph-driven cybersecurity investigation with policy-gated simulation",
    version="1.0.0",
)

# Process-local demo state only. This is not connected to real hosts or networks.
# For a multi-worker deployment, replace this with a transactional persistent simulator.
_SIMULATED_HOST_STATE: dict[str, str] = {}

# Background autonomy is explicitly started/stopped through API controls. It is
# always simulation-only and never resumes silently after a process restart.
_AUTONOMY_TASK: asyncio.Task | None = None
_AUTONOMY_STOP_EVENT: asyncio.Event | None = None
_AUTONOMY_STATUS: dict[str, Any] = {
    "running": False,
    "mode": "autonomous_simulation_only",
    "incident_ids": [],
    "interval_seconds": None,
    "cycles_completed": 0,
    "agent_runs_started": 0,
    "last_cycle": None,
    "last_agent_run": None,
    "last_error": None,
    "real_world_actions_enabled": False,
}


# --------------------------------------------------
# FalkorDB
# --------------------------------------------------

def get_graph():
    required = [
        "FALKORDB_HOST",
        "FALKORDB_USERNAME",
        "FALKORDB_PASSWORD",
    ]
    if any(not os.getenv(key) for key in required):
        raise RuntimeError("Missing required environment configuration.")

    client = FalkorDB(
        host=os.environ["FALKORDB_HOST"],
        port=int(os.getenv("FALKORDB_PORT", "54211")),
        username=os.environ["FALKORDB_USERNAME"],
        password=os.environ["FALKORDB_PASSWORD"],
        ssl=False,
        socket_connect_timeout=5,
        socket_timeout=5,
    )
    return client.select_graph(os.getenv("FALKORDB_GRAPH", "eclipse-ai"))


# --------------------------------------------------
# Request models
# --------------------------------------------------

class TriageRequest(BaseModel):
    incident_id: str = Field(default="INC-001", min_length=1, max_length=80)


class AgentRunRequest(BaseModel):
    incident_id: str = Field(default="INC-001", min_length=1, max_length=80)
    max_steps: int = Field(default=8, ge=1, le=20)
    # Test-only fault injection for demonstrating fail-closed recovery.
    # This never triggers real-world actions.
    simulate_verification_failure: bool = False


class MonitorCycleRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=80)


class AutonomyStartRequest(BaseModel):
    """Start a bounded background observation-and-response loop for known incidents."""
    incident_ids: list[str] = Field(min_length=1, max_length=25)
    interval_seconds: int = Field(default=60, ge=15, le=3600)
    max_steps: int = Field(default=8, ge=1, le=20)


class TelemetryRequest(BaseModel):
    """Validated, simulated security telemetry submitted to Eclipse AI."""
    event_id: str = Field(min_length=1, max_length=80)
    incident_id: str = Field(min_length=1, max_length=80)
    event_type: str = Field(min_length=1, max_length=80)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1, max_length=120)
    host_name: str = Field(min_length=1, max_length=120)
    environment: str = Field(default="sandbox", pattern="^(sandbox|production)$")


# --------------------------------------------------
# Existing routes
# --------------------------------------------------

@app.get("/")
def dashboard():
    file_path = BASE_DIR / "index.html"
    if not file_path.is_file():
        raise HTTPException(status_code=500, detail="Dashboard file not found.")
    return FileResponse(file_path)


@app.get("/health")
def health():
    return {"service": "Eclipse AI", "status": "running"}


@app.get("/graph/status")
def graph_status():
    try:
        result = get_graph().query("MATCH (n) RETURN count(n) AS total")
        return {
            "graph": os.getenv("FALKORDB_GRAPH", "eclipse-ai"),
            "node_count": result.result_set[0][0],
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Graph unavailable.")


# --------------------------------------------------
# Graph-based investigation
# --------------------------------------------------

def inspect_incident(incident_id: str) -> dict[str, Any]:
    query = """
    MATCH (i:Incident {id: $incident_id})
    OPTIONAL MATCH (i)-[:SUPPORTED_BY]->(e:Evidence)
    OPTIONAL MATCH (e)-[:OBSERVED_ON]->(h:Host)
    RETURN i.id AS incident_id,
           i.type AS incident_type,
           i.severity AS severity,
           i.status AS status,
           collect(DISTINCT {
               type: e.type,
               confidence: e.confidence,
               source: e.source,
               host: h.name,
               environment: h.environment
           }) AS evidence
    """

    try:
        result = get_graph().query(
            query, {"incident_id": incident_id}
        )
    except Exception:
        raise HTTPException(status_code=503, detail="Graph investigation failed.")

    if not result.result_set:
        raise HTTPException(status_code=404, detail="Incident not found.")

    incident, incident_type, severity, status, evidence = result.result_set[0]
    evidence = [item for item in evidence if item.get("type") is not None]

    high_confidence = any(
        isinstance(item.get("confidence"), (int, float))
        and item["confidence"] >= 0.90
        for item in evidence
    )
    sandbox_only = bool(evidence) and all(
        item.get("environment") == "sandbox" for item in evidence
    )
    approved = (
        str(severity).lower() == "high"
        and high_confidence
        and sandbox_only
    )

    reasons = []
    if str(severity).lower() != "high":
        reasons.append("Incident severity is not high.")
    if not high_confidence:
        reasons.append("No evidence meets the 0.90 confidence threshold.")
    if not sandbox_only:
        reasons.append("Evidence is missing or a host is outside the sandbox.")
    if approved:
        reasons.append("Severity, confidence, and sandbox checks passed.")

    return {
        "incident_id": incident,
        "type": incident_type,
        "severity": severity,
        "current_status": status,
        "evidence": evidence,
        "reasoning": {
            "high_confidence_evidence": high_confidence,
            "all_affected_hosts_in_sandbox": sandbox_only,
            "graph_evidence_count": len(evidence),
            "decision_explanation": reasons,
        },
        "policy_decision": (
            "approved_for_simulation" if approved else "blocked_pending_review"
        ),
        "proposed_action": "isolate_demo_host" if approved else None,
        "execution": "not_executed",
    }


@app.post("/triage")
def triage(request: TriageRequest):
    return inspect_incident(request.incident_id)



# --------------------------------------------------
# Simulated telemetry ingestion
# --------------------------------------------------

@app.post("/telemetry/ingest", status_code=201)
def ingest_telemetry(request: TelemetryRequest) -> dict[str, Any]:
    """
    Persist a simulated event, its incident, and its observed host.
    Repeated identical event IDs are idempotent; conflicting reuse returns 409.
    No real host or network is changed.
    """
    graph = get_graph()

    event = {
        "event_id": request.event_id,
        "incident_id": request.incident_id,
        "event_type": request.event_type,
        "severity": request.severity,
        "confidence": request.confidence,
        "source": request.source,
        "host_name": request.host_name,
        "environment": request.environment,
    }

    # Check event-ID reuse before writing, so a conflicting duplicate is rejected.
    existing_query = """
    MATCH (e:Evidence {id: $event_id})
    RETURN e.incident_id, e.type, e.severity, e.confidence,
           e.source, e.host_name, e.environment
    """
    try:
        existing_result = graph.query(
            existing_query, {"event_id": request.event_id}
        )
    except Exception:
        raise HTTPException(status_code=503, detail="Telemetry lookup failed.")

    if existing_result.result_set:
        row = existing_result.result_set[0]
        same_event = (
            row[0] == request.incident_id
            and row[1] == request.event_type
            and str(row[2]).lower() == request.severity.lower()
            and isinstance(row[3], (int, float))
            and abs(float(row[3]) - request.confidence) < 1e-9
            and row[4] == request.source
            and row[5] == request.host_name
            and row[6] == request.environment
        )
        if not same_event:
            raise HTTPException(
                status_code=409,
                detail="event_id already exists with different event data.",
            )
        return {
            "accepted": True,
            "duplicate": True,
            "simulation_only": True,
            "event_id": request.event_id,
            "incident_id": request.incident_id,
            "message": "Identical telemetry event already exists.",
        }

    write_query = """
    MERGE (i:Incident {id: $incident_id})
    ON CREATE SET i.type = 'telemetry_investigation',
                  i.severity = $severity,
                  i.status = 'open'
    MERGE (h:Host {name: $host_name})
    ON CREATE SET h.environment = $environment
    MERGE (e:Evidence {id: $event_id})
    ON CREATE SET e.incident_id = $incident_id,
                  e.type = $event_type,
                  e.severity = $severity,
                  e.confidence = $confidence,
                  e.source = $source,
                  e.host_name = $host_name,
                  e.environment = $environment,
                  e.received_at = $received_at
    MERGE (i)-[:SUPPORTED_BY]->(e)
    MERGE (e)-[:OBSERVED_ON]->(h)
    RETURN i.id, e.id, h.name, h.environment
    """

    try:
        result = graph.query(
            write_query,
            {
                **event,
                "received_at": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception:
        raise HTTPException(status_code=503, detail="Telemetry persistence failed.")

    if not result.result_set:
        raise HTTPException(status_code=503, detail="Telemetry was not persisted.")

    _, saved_event_id, saved_host_name, saved_environment = result.result_set[0]
    if saved_environment != request.environment:
        raise HTTPException(
            status_code=409,
            detail=(
                "The host already exists with a different environment. "
                "Use a distinct host_name or reconcile the host record first."
            ),
        )

    return {
        "accepted": True,
        "duplicate": False,
        "simulation_only": True,
        "event_id": saved_event_id,
        "incident_id": request.incident_id,
        "host_name": saved_host_name,
        "environment": saved_environment,
        "message": "Telemetry event persisted to FalkorDB.",
    }


# --------------------------------------------------
# Graph-grounded context and closed-loop monitoring
# --------------------------------------------------

def get_related_graph_context(incident_id: str) -> dict[str, Any]:
    """Fetch the incident's hosts/evidence and related incidents sharing those hosts."""
    query = """
    MATCH (i:Incident {id: $incident_id})
    OPTIONAL MATCH (i)-[:SUPPORTED_BY]->(e:Evidence)-[:OBSERVED_ON]->(h:Host)
    WITH i, collect(DISTINCT {host: h.name, environment: h.environment,
                              evidence_type: e.type, confidence: e.confidence,
                              source: e.source}) AS evidence_context
    OPTIONAL MATCH (related:Incident)-[:SUPPORTED_BY]->(re:Evidence)-[:OBSERVED_ON]->(rh:Host)
    WHERE related.id <> i.id AND any(item IN evidence_context WHERE item.host = rh.name)
    RETURN i.id, i.severity, evidence_context,
           collect(DISTINCT {incident_id: related.id, severity: related.severity,
                             status: related.status, shared_host: rh.name,
                             evidence_type: re.type}) AS related_incidents
    """
    try:
        result = get_graph().query(query, {"incident_id": incident_id})
    except Exception:
        raise HTTPException(status_code=503, detail="Graph context retrieval failed.")
    if not result.result_set:
        raise HTTPException(status_code=404, detail="Incident not found.")
    row = result.result_set[0]
    evidence_context = [x for x in (row[2] or []) if x.get("host") is not None]
    related = [x for x in (row[3] or []) if x.get("incident_id") is not None]
    return {
        "incident_id": row[0],
        "severity": row[1],
        "evidence_context": evidence_context,
        "related_incidents": related,
        "related_incident_count": len(related),
        "graph_grounded": True,
    }


@app.get("/agent/context/{incident_id}")
def agent_context(incident_id: str):
    """Expose connected graph context used to ground triage and planning."""
    if not incident_id or len(incident_id) > 80:
        raise HTTPException(status_code=422, detail="Invalid incident_id.")
    context = get_related_graph_context(incident_id)
    context["historical_memory"] = retrieve_agent_memory(incident_id, limit=10)
    return context


@app.post("/agent/monitor-cycle")
def monitor_cycle(request: MonitorCycleRequest) -> dict[str, Any]:
    """Run one persistent observation cycle; callers schedule repeated checks externally.

    It never executes containment. It compares graph-grounded incident state with the
    previous stored observation and returns a bounded next-step recommendation.
    """
    incident = inspect_incident(request.incident_id)
    context = get_related_graph_context(request.incident_id)
    memory = retrieve_agent_memory(request.incident_id, limit=10)
    signature_payload = {
        "severity": incident.get("severity"),
        "status": incident.get("current_status"),
        "evidence": sorted([
            {"type": x.get("type"), "confidence": x.get("confidence"),
             "host": x.get("host"), "environment": x.get("environment"),
             "source": x.get("source")}
            for x in incident.get("evidence", [])
        ], key=lambda x: json.dumps(x, sort_keys=True, default=str)),
        "related_incidents": sorted(context.get("related_incidents", []),
                                    key=lambda x: json.dumps(x, sort_keys=True, default=str)),
    }
    fingerprint = hashlib.sha256(json.dumps(signature_payload, sort_keys=True, default=str).encode()).hexdigest()
    cycle_id = str(uuid4())
    observed_at = datetime.now(timezone.utc).isoformat()
    try:
        previous = get_graph().query(
            """MATCH (m:MonitorCycle {incident_id: $incident_id})
               RETURN m.fingerprint, m.cycle_id, m.observed_at
               ORDER BY m.observed_at DESC LIMIT 1""",
            {"incident_id": request.incident_id},
        )
        prior = previous.result_set[0] if previous.result_set else None
        changed = bool(prior and prior[0] != fingerprint)
        decision = "rerun_triage" if changed else ("baseline_observed" if prior is None else "continue_monitoring")
        next_action = (
            "Re-inspect changed graph evidence and re-run the independent safety gate; do not auto-execute."
            if changed else
            "No material graph change detected; await the next scheduled observation cycle."
        )
        saved = get_graph().query(
            """MERGE (m:MonitorCycle {cycle_id: $cycle_id})
               SET m.incident_id = $incident_id, m.fingerprint = $fingerprint,
                   m.observed_at = $observed_at, m.change_detected = $changed,
                   m.decision = $decision
               RETURN m.cycle_id""",
            {"cycle_id": cycle_id, "incident_id": request.incident_id,
             "fingerprint": fingerprint, "observed_at": observed_at,
             "changed": changed, "decision": decision},
        )
        if not saved.result_set:
            raise RuntimeError("Monitor cycle was not persisted")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Monitoring cycle could not be persisted.")
    return {
        "cycle_id": cycle_id,
        "incident_id": request.incident_id,
        "observed_at": observed_at,
        "change_detected": changed,
        "decision": decision,
        "next_action": next_action,
        "graph_context": context,
        "memory_summary": {
            "available": memory.get("available", False),
            "records_considered": memory.get("records_considered", 0),
            "verified_recoveries": memory.get("verified_recoveries", 0),
        },
        "execution_performed": False,
        "real_world_actions_enabled": False,
        "monitoring_note": "This endpoint performs one cycle per request; schedule repeated requests externally for continuous monitoring.",
    }


async def _autonomy_worker(incident_ids: list[str], interval_seconds: int, max_steps: int,
                           stop_event: asyncio.Event) -> None:
    """Observe continuously; run the bounded agent only for a new baseline or changed graph.

    Every response remains sandbox simulation-only. A blocked policy, failed verification,
    or graph error is recorded and never escalated into a real-world action.
    """
    while not stop_event.is_set():
        for incident_id in incident_ids:
            if stop_event.is_set():
                break
            try:
                observation = await asyncio.to_thread(
                    monitor_cycle, MonitorCycleRequest(incident_id=incident_id)
                )
                _AUTONOMY_STATUS["cycles_completed"] += 1
                _AUTONOMY_STATUS["last_cycle"] = {
                    "incident_id": incident_id,
                    "cycle_id": observation.get("cycle_id"),
                    "decision": observation.get("decision"),
                    "change_detected": observation.get("change_detected"),
                    "observed_at": observation.get("observed_at"),
                }
                _AUTONOMY_STATUS["last_error"] = None

                # First observation establishes a baseline and evaluates it once.
                # Later runs happen only when the graph fingerprint changes.
                if observation.get("decision") in {"baseline_observed", "rerun_triage"}:
                    run_result = await asyncio.to_thread(
                        run_agent,
                        AgentRunRequest(incident_id=incident_id, max_steps=max_steps),
                    )
                    _AUTONOMY_STATUS["agent_runs_started"] += 1
                    _AUTONOMY_STATUS["last_agent_run"] = {
                        "incident_id": incident_id,
                        "run_id": run_result.get("run_id"),
                        "agent_status": run_result.get("agent_status"),
                        "verified": run_result.get("verified"),
                        "simulation_only": run_result.get("simulation_only", True),
                        "completed_at": run_result.get("completed_at"),
                    }
            except HTTPException as exc:
                _AUTONOMY_STATUS["last_error"] = f"HTTP {exc.status_code}: {exc.detail}"
            except Exception as exc:
                # Do not expose connection strings, credentials, or exception internals.
                _AUTONOMY_STATUS["last_error"] = f"Autonomy cycle failed ({type(exc).__name__})."

        if stop_event.is_set():
            break
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass


@app.get("/agent/autonomy/status")
async def autonomy_status() -> dict[str, Any]:
    """Return current process-local autonomy state and safety boundary."""
    return dict(_AUTONOMY_STATUS)


@app.post("/agent/autonomy/start")
async def start_autonomy(request: AutonomyStartRequest) -> dict[str, Any]:
    """Start a persistent-graph-backed, bounded simulation-only background loop."""
    global _AUTONOMY_TASK, _AUTONOMY_STOP_EVENT
    if _AUTONOMY_TASK is not None and not _AUTONOMY_TASK.done():
        raise HTTPException(status_code=409, detail="Autonomy loop is already running.")

    incident_ids = list(dict.fromkeys(item.strip() for item in request.incident_ids))
    if any(not item or len(item) > 80 for item in incident_ids):
        raise HTTPException(status_code=422, detail="Each incident ID must be 1-80 characters.")

    # Fail before launching if any requested incident is absent or the graph is down.
    for incident_id in incident_ids:
        await asyncio.to_thread(inspect_incident, incident_id)

    _AUTONOMY_STOP_EVENT = asyncio.Event()
    _AUTONOMY_STATUS.update({
        "running": True,
        "mode": "autonomous_simulation_only",
        "incident_ids": incident_ids,
        "interval_seconds": request.interval_seconds,
        "max_steps": request.max_steps,
        "cycles_completed": 0,
        "agent_runs_started": 0,
        "last_cycle": None,
        "last_agent_run": None,
        "last_error": None,
        "real_world_actions_enabled": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    _AUTONOMY_TASK = asyncio.create_task(
        _autonomy_worker(incident_ids, request.interval_seconds, request.max_steps, _AUTONOMY_STOP_EVENT),
        name="eclipse-ai-autonomy-loop",
    )
    return {
        "started": True,
        "message": "Autonomy loop started. It observes the graph continuously and runs the bounded agent only for a baseline or material graph change.",
        **dict(_AUTONOMY_STATUS),
    }


@app.post("/agent/autonomy/stop")
async def stop_autonomy() -> dict[str, Any]:
    """Stop future observation cycles and wait for the current bounded cycle to finish."""
    global _AUTONOMY_TASK, _AUTONOMY_STOP_EVENT
    task = _AUTONOMY_TASK
    if task is None or task.done():
        _AUTONOMY_STATUS["running"] = False
        return {"stopped": True, "message": "Autonomy loop is not running.", **dict(_AUTONOMY_STATUS)}

    if _AUTONOMY_STOP_EVENT is not None:
        _AUTONOMY_STOP_EVENT.set()
    try:
        await asyncio.wait_for(task, timeout=12)
    except asyncio.TimeoutError:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    finally:
        _AUTONOMY_TASK = None
        _AUTONOMY_STOP_EVENT = None
        _AUTONOMY_STATUS["running"] = False
        _AUTONOMY_STATUS["stopped_at"] = datetime.now(timezone.utc).isoformat()

    return {"stopped": True, "message": "Autonomy loop stopped safely.", **dict(_AUTONOMY_STATUS)}


# --------------------------------------------------
# Independent policy and simulation tools
# --------------------------------------------------

def safety_gate(incident: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons = []
    evidence = incident["evidence"]

    if str(incident["severity"]).lower() != "high":
        reasons.append("Severity must be high.")

    if not any(
        isinstance(item.get("confidence"), (int, float))
        and item["confidence"] >= 0.90
        for item in evidence
    ):
        reasons.append("High-confidence evidence is required.")

    if not evidence or not all(
        item.get("environment") == "sandbox" for item in evidence
    ):
        reasons.append("All affected hosts must be in the sandbox.")

    if incident["proposed_action"] != "isolate_demo_host":
        reasons.append("Action is not allowlisted.")

    if os.getenv("ECLIPSE_KILL_SWITCH", "false").lower() in {
        "1", "true", "yes", "on"
    }:
        reasons.append("Emergency kill switch is enabled.")

    return not reasons, reasons


def simulated_executor(run_id: str, incident_id: str) -> dict[str, Any]:
    """Apply an action to the in-memory simulator only; never touch a real host."""
    _SIMULATED_HOST_STATE[incident_id] = "isolated"
    return {
        "action_id": f"SIM-{run_id[:8]}",
        "incident_id": incident_id,
        "action": "isolate_demo_host",
        "target": "sandbox_demo_only",
        "result": "simulated_success",
        "simulated_state": _SIMULATED_HOST_STATE[incident_id],
        "real_host_changed": False,
    }


def verify_simulation(
    action: dict[str, Any],
    force_failure: bool = False,
) -> bool:
    """Independently inspect the simulator state; optional fault injection is test-only."""
    if force_failure:
        return False
    incident_id = action.get("incident_id")
    return (
        action.get("result") == "simulated_success"
        and action.get("real_host_changed") is False
        and action.get("target") == "sandbox_demo_only"
        and action.get("action") == "isolate_demo_host"
        and _SIMULATED_HOST_STATE.get(incident_id) == "isolated"
        and action.get("simulated_state") == "isolated"
    )


def simulated_recovery(
    run_id: str,
    incident_id: str,
    failed_action: dict[str, Any] | None,
) -> dict[str, Any]:
    """Roll back the in-memory demo state to baseline; no real system is changed."""
    previous_state = _SIMULATED_HOST_STATE.get(incident_id, "unknown")
    _SIMULATED_HOST_STATE[incident_id] = "restored"
    return {
        "recovery_id": f"REC-{run_id[:8]}",
        "incident_id": incident_id,
        "failed_action_id": (
            failed_action.get("action_id") if failed_action else None
        ),
        "previous_simulated_state": previous_state,
        "simulated_state": _SIMULATED_HOST_STATE[incident_id],
        "result": "simulated_rollback_applied",
        "recovery_resolved": True,
        "requires_reverification": True,
        "real_host_changed": False,
        "message": (
            "The simulator state was rolled back to baseline. The agent must "
            "verify the restored state before reporting recovery success."
        ),
    }


def verify_recovery(recovery: dict[str, Any]) -> bool:
    """Verify recovery against the simulator state, not just the recovery response."""
    incident_id = recovery.get("incident_id")
    return (
        recovery.get("result") == "simulated_rollback_applied"
        and recovery.get("recovery_resolved") is True
        and recovery.get("real_host_changed") is False
        and recovery.get("simulated_state") == "restored"
        and _SIMULATED_HOST_STATE.get(incident_id) == "restored"
    )


# --------------------------------------------------
# Persistent agent memory
# --------------------------------------------------

def persist_agent_run(
    run_id: str,
    incident_id: str,
    agent_status: str,
    execution: str,
    verified: bool,
    steps: list[dict[str, Any]],
    completed_at: str,
    recovery_attempted: bool = False,
    stop_reason: str = "",
    autonomy_summary: dict[str, Any] | None = None,
) -> bool:
    """Persist run outcome, planner decisions, stop reason, and recovery history."""
    query = """
    MATCH (i:Incident {id: $incident_id})
    MERGE (r:AgentRun {run_id: $run_id})
    SET r.incident_id = $incident_id,
        r.agent_status = $agent_status,
        r.execution = $execution,
        r.verified = $verified,
        r.step_count = $step_count,
        r.steps_json = $steps_json,
        r.decision_trace_json = $decision_trace_json,
        r.autonomy_json = $autonomy_json,
        r.recovery_attempted = $recovery_attempted,
        r.stop_reason = $stop_reason,
        r.completed_at = $completed_at,
        r.simulation_only = true
    MERGE (r)-[:INVESTIGATED]->(i)
    RETURN r.run_id
    """

    try:
        result = get_graph().query(
            query,
            {
                "run_id": run_id,
                "incident_id": incident_id,
                "agent_status": agent_status,
                "execution": execution,
                "verified": verified,
                "step_count": len(steps),
                "steps_json": json.dumps(steps, default=str),
                "decision_trace_json": json.dumps((autonomy_summary or {}).get("decision_trace", []), default=str),
                "autonomy_json": json.dumps(autonomy_summary or {}, default=str),
                "recovery_attempted": recovery_attempted,
                "stop_reason": stop_reason,
                "completed_at": completed_at,
            },
        )
        return bool(result.result_set)
    except Exception:
        return False


def agent_stop_reason(agent_status: str, verified: bool) -> str:
    """Return a user-readable explanation for why the agent stopped."""
    if verified and agent_status == "recovery_verified":
        return "Recovery restored the simulator baseline and passed independent re-verification."
    if verified:
        return "The simulated action met the verification goal."
    if agent_status == "blocked_pending_review":
        return "Safety policy blocked execution; human review is required."
    if agent_status == "step_limit_reached":
        return "Execution budget exhausted before a verified terminal state; stopped safely."
    if agent_status == "verification_failed":
        return "The action or recovery could not be verified; stopped safely for human review."
    return "The planner reached a safe terminal state."


def finish_run(
    run_id: str,
    incident_id: str,
    agent_status: str,
    execution: str,
    verified: bool,
    steps: list[dict[str, Any]],
    recovery_attempted: bool = False,
    stop_reason: str = "",
    autonomy_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    completed_at = datetime.now(timezone.utc).isoformat()

    memory_saved = persist_agent_run(
        run_id=run_id,
        incident_id=incident_id,
        agent_status=agent_status,
        execution=execution,
        verified=verified,
        steps=steps,
        completed_at=completed_at,
        recovery_attempted=recovery_attempted,
        stop_reason=stop_reason or agent_stop_reason(agent_status, verified),
        autonomy_summary=autonomy_summary,
    )

    return {
        "run_id": run_id,
        "incident_id": incident_id,
        "agent_status": agent_status,
        "simulation_only": True,
        "steps": steps,
        "execution": execution,
        "verified": verified,
        "recovery_attempted": recovery_attempted,
        "memory_persisted": memory_saved,
        "stop_reason": stop_reason or agent_stop_reason(agent_status, verified),
        "autonomy": autonomy_summary or {
            "mode": "bounded_observation_driven",
            "planner": "deterministic_goal_state",
            "human_safety_boundary": True,
            "real_world_actions_enabled": False,
        },
        "completed_at": completed_at,
    }


def retrieve_agent_memory(incident_id: str, limit: int = 10) -> dict[str, Any]:
    """Retrieve durable run history to inform the next incident/monitoring cycle."""
    query = """
    MATCH (r:AgentRun)
    WHERE r.incident_id = $incident_id
    RETURN r.run_id, r.incident_id, r.agent_status, r.execution,
           r.verified, r.recovery_attempted, r.steps_json, r.completed_at
    ORDER BY r.completed_at DESC
    LIMIT $limit
    """
    try:
        result = get_graph().query(query, {"incident_id": incident_id, "limit": limit})
        records = []
        for row in result.result_set:
            try:
                saved_steps = json.loads(row[6] or "[]")
            except (TypeError, json.JSONDecodeError):
                saved_steps = []
            # Older AgentRun records may not have the recovery_attempted property.
            # Infer it from the persisted audit trail/status for backward compatibility.
            inferred_recovery = (
                bool(row[5])
                or row[2] == "recovery_verified"
                or any(step.get("tool") == "recovery" for step in saved_steps if isinstance(step, dict))
            )
            records.append({
                "run_id": row[0], "incident_id": row[1],
                "agent_status": row[2], "execution": row[3],
                "verified": bool(row[4]), "recovery_attempted": inferred_recovery,
                "steps": saved_steps, "completed_at": row[7],
            })
        return {
            "available": True,
            "incident_id": incident_id,
            "records_considered": len(records),
            "verified_runs": sum(1 for item in records if item["verified"]),
            "verified_recoveries": sum(1 for item in records if item["verified"] and item["recovery_attempted"]),
            "recent_runs": records,
            "memory_policy": "Historical records inform planning; safety policy is always re-evaluated independently.",
        }
    except Exception:
        # Memory retrieval failure must not bypass the independent safety gate.
        return {
            "available": False, "incident_id": incident_id,
            "records_considered": 0, "verified_runs": 0,
            "verified_recoveries": 0, "recent_runs": [],
            "memory_policy": "History unavailable; proceed only under current-run evidence and safety policy.",
        }


@app.get("/agent/memory")
def get_agent_memory(
    incident_id: str = Query(..., min_length=1, max_length=80),
    limit: int = Query(default=10, ge=1, le=50),
):
    """Expose durable decisions/outcomes/recovery history for the next cycle."""
    memory = retrieve_agent_memory(incident_id, limit)
    if not memory["available"]:
        raise HTTPException(status_code=503, detail="Could not retrieve durable agent memory from FalkorDB.")
    return memory


@app.get("/agent/runs")
def get_agent_runs(
    incident_id: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Retrieve recent saved runs, optionally filtered by incident."""
    query = """
    MATCH (r:AgentRun)
    WHERE $incident_id IS NULL OR r.incident_id = $incident_id
    RETURN r.run_id, r.incident_id, r.agent_status,
           r.execution, r.verified, r.step_count,
           r.steps_json, r.completed_at, r.simulation_only,
           r.decision_trace_json, r.recovery_attempted, r.stop_reason, r.autonomy_json
    ORDER BY r.completed_at DESC
    LIMIT $limit
    """

    try:
        result = get_graph().query(
            query,
            {"incident_id": incident_id, "limit": limit},
        )
        runs = []

        for row in result.result_set:
            try:
                steps = json.loads(row[6] or "[]")
            except (TypeError, json.JSONDecodeError):
                steps = []

            runs.append({
                "run_id": row[0],
                "incident_id": row[1],
                "agent_status": row[2],
                "execution": row[3],
                "verified": row[4],
                "step_count": row[5],
                "steps": steps,
                "completed_at": row[7],
                "simulation_only": row[8],
                "decision_trace": json.loads(row[9] or "[]") if len(row) > 9 and row[9] else [],
                "recovery_attempted": row[10] if len(row) > 10 else False,
                "stop_reason": row[11] if len(row) > 11 else None,
                "autonomy": json.loads(row[12] or "{}") if len(row) > 12 and row[12] else {},
            })

        return {"count": len(runs), "runs": runs}
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Could not retrieve agent memory from FalkorDB.",
        )


# --------------------------------------------------
# Adaptive planning tools
# --------------------------------------------------

def plan_next_tool(
    incident: dict[str, Any] | None,
    previous_result: dict[str, Any] | None,
    completed_tools: list[str],
) -> dict[str, str]:
    """Replan toward a verified goal from observations and completed tool outcomes.

    This is a deterministic goal-state planner, not an LLM. Every tool choice is
    derived from the current run state; the execution budget remains enforced by
    the caller and safety policy remains independent of this planner.
    """
    if "inspect_incident" not in completed_tools:
        return {
            "tool": "inspect_incident",
            "reason": "Incident context has not been observed yet.",
        }

    if "safety_gate" not in completed_tools:
        return {
            "tool": "safety_gate",
            "reason": "The independent safety policy must evaluate the observed incident.",
        }

    if previous_result and previous_result.get("verified") is False:
        if "diagnose_failure" not in completed_tools:
            memory = (incident or {}).get("historical_memory", {})
            diagnosis = (previous_result or {}).get("diagnosis", {})
            observed_state = diagnosis.get("observed_simulated_state", (previous_result or {}).get("observed_simulated_state", "unknown"))
            if memory.get("verified_recoveries", 0) > 0:
                reason = ("Observed verification failure at state " + str(observed_state) +
                          "; historical verified recoveries support one bounded rollback, "
                          "but the independent safety policy must still approve any execution.")
            else:
                reason = ("Observed verification failure at state " + str(observed_state) +
                          "; diagnose the current result and choose only a bounded, simulation-only recovery.")
            return {"tool": "diagnose_failure", "reason": reason}
        if "recovery" not in completed_tools:
            return {
                "tool": "recovery",
                "reason": "Failure diagnosis recommends one simulation-only rollback; do not retry the action.",
            }
        if "verify_recovery" not in completed_tools:
            return {
                "tool": "verify_recovery",
                "reason": "Recovery was applied; independently inspect the restored simulator state.",
            }
        return {
            "tool": "stop",
            "reason": "Recovery could not be verified; stop safely and require human review.",
        }

    if not incident or incident.get("policy_decision") != "approved_for_simulation":
        return {
            "tool": "stop",
            "reason": "Policy did not approve the simulation.",
        }

    if "simulated_executor" not in completed_tools:
        return {
            "tool": "simulated_executor",
            "reason": "The policy-approved sandbox simulation is available.",
        }

    if "verify_simulation" not in completed_tools:
        return {
            "tool": "verify_simulation",
            "reason": "The simulated outcome must be checked before reporting success.",
        }

    return {
        "tool": "stop",
        "reason": "The plan is complete; no further action is required.",
    }


# --------------------------------------------------
# Bounded adaptive agent loop
# --------------------------------------------------

@app.post("/agent/run")
def run_agent(request: AgentRunRequest) -> dict[str, Any]:
    run_id = str(uuid4())
    steps: list[dict[str, Any]] = []
    completed_tools: list[str] = []
    incident: dict[str, Any] | None = None
    previous_result: dict[str, Any] | None = None
    action: dict[str, Any] | None = None
    allowed = False
    verified = False
    recovery_attempted = False
    status = "step_limit_reached"
    execution = "not_executed"
    decision_trace: list[dict[str, Any]] = []
    stop_reason = "Execution budget exhausted before a verified terminal state; stopped safely."

    for step_number in range(1, request.max_steps + 1):
        # Re-evaluate the next action after every observation/result. Never execute
        # a precomputed plan blindly.
        plan = plan_next_tool(incident, previous_result, completed_tools)
        tool = plan["tool"]
        decision_trace.append({
            "decision": step_number,
            "chosen_tool": tool,
            "reason": plan["reason"],
            "observed_incident": incident is not None,
            "completed_tools": list(completed_tools),
        })

        if tool == "stop":
            if verified:
                status = "simulation_verified"
            elif not allowed:
                status = "blocked_pending_review"
            elif action is not None:
                status = "verification_failed"
            break

        step: dict[str, Any] = {
            "step": step_number,
            "tool": tool,
            "planner_reason": plan["reason"],
        }

        if tool == "inspect_incident":
            incident = inspect_incident(request.incident_id)
            historical_memory = retrieve_agent_memory(request.incident_id, limit=10)
            incident["historical_memory"] = historical_memory
            try:
                graph_context = get_related_graph_context(request.incident_id)
            except HTTPException:
                graph_context = {"graph_grounded": False, "related_incidents": []}
            incident["graph_context"] = graph_context
            previous_result = {
                "incident_id": incident["incident_id"],
                "severity": incident["severity"],
                "evidence_count": len(incident["evidence"]),
                "policy_decision": incident["policy_decision"],
            }
            previous_result["related_incident_count"] = graph_context.get("related_incident_count", 0)
            step["observation"] = previous_result
            step["graph_context"] = {
                "graph_grounded": graph_context.get("graph_grounded", False),
                "related_incident_count": graph_context.get("related_incident_count", 0),
            }
            step["historical_memory"] = {
                "available": historical_memory.get("available", False),
                "records_considered": historical_memory.get("records_considered", 0),
                "verified_runs": historical_memory.get("verified_runs", 0),
                "verified_recoveries": historical_memory.get("verified_recoveries", 0),
            }
            completed_tools.append(tool)

        elif tool == "safety_gate":
            if incident is None:
                status = "blocked_pending_review"
                step["result"] = "blocked"
                step["reasons"] = ["Incident context is unavailable."]
                steps.append(step)
                break

            allowed, reasons = safety_gate(incident)
            previous_result = {"approved": allowed, "reasons": reasons}
            step["result"] = "approved" if allowed else "blocked"
            step["reasons"] = reasons
            completed_tools.append(tool)
            if not allowed:
                status = "blocked_pending_review"

        elif tool == "simulated_executor":
            # Defence in depth: never execute unless the independent gate approved.
            if not allowed or incident is None:
                status = "blocked_pending_review"
                step["result"] = "blocked_by_execution_guard"
                steps.append(step)
                break
            # Re-check the independent safety policy at the point of action.
            # This catches a newly enabled kill switch or changed incident policy.
            reapproved, recheck_reasons = safety_gate(incident)
            step["pre_execution_policy_recheck"] = {
                "approved": reapproved,
                "reasons": recheck_reasons,
            }
            if not reapproved:
                allowed = False
                status = "blocked_pending_review"
                step["result"] = "blocked_by_final_policy_recheck"
                step["reasons"] = recheck_reasons
                steps.append(step)
                stop_reason = "Final independent policy re-check blocked execution; human review is required."
                break
            action = simulated_executor(run_id, request.incident_id)
            execution = "simulated"
            previous_result = action
            step["result"] = action
            completed_tools.append(tool)

        elif tool == "verify_simulation":
            # Fault injection deliberately fails only the first verification so the
            # recovery-and-reverification path can be demonstrated end to end.
            verified = bool(
                action is not None
                and verify_simulation(
                    action,
                    force_failure=(request.simulate_verification_failure and not recovery_attempted),
                )
            )
            previous_result = {"verified": verified, "observed_simulated_state": _SIMULATED_HOST_STATE.get(request.incident_id, "unknown")}
            step["verified"] = verified
            completed_tools.append(tool)
            if verified:
                status = "simulation_verified"
                execution = "simulated_success"
            else:
                status = "verification_failed"

        elif tool == "diagnose_failure":
            # Record an explicit diagnosis from observed results; no real-world action.
            last_verification = next(
                (item for item in reversed(steps) if item.get("tool") == "verify_simulation"),
                {},
            )
            diagnosis = {
                "failure_detected": last_verification.get("verified") is False,
                "failed_tool": "verify_simulation",
                "observed_simulated_state": _SIMULATED_HOST_STATE.get(request.incident_id, "unknown"),
                "recommended_response": "single_simulated_rollback",
                "real_host_changed": False,
            }
            step["result"] = diagnosis
            completed_tools.append(tool)
            previous_result = {"verified": False, "diagnosis": diagnosis}
            status = "verification_failed"

        elif tool == "recovery":
            # Exactly one bounded rollback in the simulator; never retry the action.
            recovery_attempted = True
            recovery = simulated_recovery(run_id, request.incident_id, action)
            previous_result = {"verified": False, "diagnosis": (previous_result or {}).get("diagnosis"), "recovery": recovery}
            step["result"] = recovery
            completed_tools.append(tool)
            status = "verification_failed"

        elif tool == "verify_recovery":
            recovery_record = (previous_result or {}).get("recovery", {})
            recovery_verified = verify_recovery(recovery_record)
            step["verified"] = recovery_verified
            step["result"] = {
                "recovery_verified": recovery_verified,
                "simulated_state": _SIMULATED_HOST_STATE.get(request.incident_id, "unknown"),
                "real_host_changed": False,
            }
            completed_tools.append(tool)
            previous_result = {"verified": not recovery_verified}
            if recovery_verified:
                verified = True
                status = "recovery_verified"
                execution = "simulated_recovered"
            else:
                verified = False
                status = "verification_failed"

        else:
            status = "blocked_pending_review"
            step["result"] = "unknown_tool_blocked"
            steps.append(step)
            break

        steps.append(step)

        if status == "blocked_pending_review":
            stop_reason = "Safety policy blocked execution; human review is required."
            break
        if verified:
            # Preserve the terminal state that accurately describes the outcome.
            status = (
                "recovery_verified"
                if execution == "simulated_recovered"
                else "simulation_verified"
            )
            stop_reason = agent_stop_reason(status, verified)
            break

    if not verified and status == "verification_failed":
        stop_reason = agent_stop_reason(status, verified)
    elif not verified and status == "step_limit_reached":
        stop_reason = agent_stop_reason(status, verified)

    return finish_run(
        run_id,
        request.incident_id,
        status,
        execution,
        verified,
        steps,
        recovery_attempted=recovery_attempted,
        stop_reason=stop_reason,
        autonomy_summary={
            "mode": "bounded_observation_driven",
            "planner": "deterministic_goal_state",
            "replans": len(decision_trace),
            "max_steps": request.max_steps,
            "steps_used": len(steps),
            "goal": "verified_simulated_outcome_or_safe_stop",
            "human_safety_boundary": True,
            "real_world_actions_enabled": False,
            "decision_trace": decision_trace,
        },
    )
