
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from falkordb import FalkorDB
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = FastAPI(
    title="Eclipse AI",
    description="Graph-driven incident triage with policy-gated simulation",
    version="0.3.0",
)


def get_graph():
    required = [
        "FALKORDB_HOST",
        "FALKORDB_USERNAME",
        "FALKORDB_PASSWORD",
    ]
    missing = [key for key in required if not os.getenv(key)]
    if missing:
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


class TriageRequest(BaseModel):
    incident_id: str = Field(default="INC-001", min_length=1, max_length=80)


@app.get("/")
def dashboard():
    dashboard_file = BASE_DIR / "index.html"
    if not dashboard_file.is_file():
        raise HTTPException(status_code=500, detail="Dashboard file not found.")
    return FileResponse(dashboard_file)


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
        raise HTTPException(
            status_code=503,
            detail="Graph unavailable; check server configuration.",
        )


@app.post("/triage")
def triage(request: TriageRequest) -> dict[str, Any]:
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
        result = get_graph().query(query, {"incident_id": request.incident_id})
        if not result.result_set:
            raise HTTPException(status_code=404, detail="Incident not found.")

        row = result.result_set[0]
        incident_id, incident_type, severity, status, evidence = row

        evidence = [
            item for item in evidence
            if item.get("type") is not None
        ]

        high_confidence = any(
            isinstance(item.get("confidence"), (int, float))
            and item["confidence"] >= 0.90
            for item in evidence
        )
        sandbox_only = bool(evidence) and all(
            item.get("environment") == "sandbox"
            for item in evidence
        )

        approved = (
            str(severity).lower() == "high"
            and high_confidence
            and sandbox_only
        )

        decision = (
            "approved_for_simulation"
            if approved
            else "blocked_pending_review"
        )

        reasons = []
        if str(severity).lower() != "high":
            reasons.append("Incident severity is not high.")
        if not high_confidence:
            reasons.append(
                "No evidence meets the 0.90 confidence threshold."
            )
        if not sandbox_only:
            reasons.append(
                "Evidence is missing or not all affected hosts are in the sandbox."
            )
        if approved:
            reasons.append(
                "High severity, high-confidence evidence, and sandbox-only "
                "environment satisfy the simulation policy."
            )

        return {
            "incident_id": incident_id,
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
            "policy_decision": decision,
            "proposed_action": "isolate_demo_host" if approved else None,
            "execution": "not_executed",
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Triage failed; check server configuration.",
        )
