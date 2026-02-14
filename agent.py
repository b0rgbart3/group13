from typing import TypedDict, Dict, Any, List
from langgraph.graph import StateGraph, END


# -------------------------
# STATE DEFINITION
# -------------------------

class SecurityState(TypedDict, total=False):
    selected_vuln: str
    logs: List[Dict[str, Any]]
    client: Any

    sequence_features: Dict[str, float]
    payload_features: Dict[str, float]
    behavior_features: Dict[str, float]

    risk_score: float
    risk_factors: List[str]

    alert_type: str | None
    alert_confidence: float | None


# -------------------------
# NODES
# -------------------------

def log_ingest_node(state: SecurityState) -> SecurityState:
    state["logs"] = state.get("logs", [])
    state["selected_vuln"] = state.get("selected_vuln", "")
    return state


def sequence_analyzer_node(state: SecurityState) -> SecurityState:
    logs = state["logs"]

    login_velocity = max((0.9 if e.get("endpoint") == "/api/login" and e.get("response_code") == 401 else 0.1 for e in logs), default=0.1)
    sequential_object_access = max((0.85 if "/api/users/" in e.get("endpoint", "") else 0.1 for e in logs), default=0.1)
    request_frequency = min(len(logs) / 10.0, 1.0)
    repeated_action_score = max((0.8 if e.get("endpoint") == "/api/orders" else 0.1 for e in logs), default=0.1)

    state["sequence_features"] = {
        "login_velocity": login_velocity,
        "sequential_object_access": sequential_object_access,
        "request_frequency": request_frequency,
        "repeated_action_score": repeated_action_score
    }
    return state


def payload_inspector_node(state: SecurityState) -> SecurityState:
    logs = state["logs"]

    sql_injection_score = 0.1
    unexpected_field_score = 0.1
    for e in logs:
        params = str(e.get("params", "")) + str(e.get("body", ""))
        if "OR 1=1" in params or "UNION SELECT" in params:
            sql_injection_score = 0.95
        if "isAdmin" in params or "role" in params:
            unexpected_field_score = 0.9

    state["payload_features"] = {
        "sql_injection_score": sql_injection_score,
        "unexpected_field_score": unexpected_field_score,
        "command_injection_score": 0.1
    }
    return state


def behavior_profiler_node(state: SecurityState) -> SecurityState:
    logs = state["logs"]

    role_deviation_score = max((0.75 if e.get("user_id") == 456 else 0.2 for e in logs), default=0.2)
    user_agent_anomaly_score = max((0.8 if "sqlmap" in e.get("user_agent", "") else 0.2 for e in logs), default=0.2)

    state["behavior_features"] = {
        "geo_deviation_score": 0.6,
        "role_deviation_score": role_deviation_score,
        "user_agent_anomaly_score": user_agent_anomaly_score
    }
    return state


def risk_aggregator_node(state: SecurityState) -> SecurityState:
    sequence_score = max(state["sequence_features"].values())
    payload_score = max(state["payload_features"].values())
    behavior_score = max(state["behavior_features"].values())

    state["risk_score"] = (
        0.4 * sequence_score +
        0.4 * payload_score +
        0.2 * behavior_score
    )

    combined = {
        **state["sequence_features"],
        **state["payload_features"],
        **state["behavior_features"]
    }

    state["risk_factors"] = [
        k for k, v in combined.items() if v > 0.7
    ]

    return state


def alert_classifier_node(state: SecurityState) -> SecurityState:
    pf = state["payload_features"]
    sf = state["sequence_features"]

    if pf["sql_injection_score"] > 0.8:
        state["alert_type"] = "SQL_INJECTION"
    elif sf["login_velocity"] > 0.8:
        state["alert_type"] = "CREDENTIAL_STUFFING"
    elif sf["sequential_object_access"] > 0.8:
        state["alert_type"] = "POSSIBLE_IDOR"
    elif sf["repeated_action_score"] > 0.8:
        state["alert_type"] = "BUSINESS_LOGIC_ABUSE"
    else:
        state["alert_type"] = None

    state["alert_confidence"] = state["risk_score"]
    return state


# -------------------------
# GRAPH CONSTRUCTION
# -------------------------

def create_real_agentic_workflow():
    builder = StateGraph(SecurityState)

    builder.add_node("log_ingest", log_ingest_node)
    builder.add_node("sequence_analyzer", sequence_analyzer_node)
    builder.add_node("payload_inspector", payload_inspector_node)
    builder.add_node("behavior_profiler", behavior_profiler_node)
    builder.add_node("risk_aggregator", risk_aggregator_node)
    builder.add_node("alert_classifier", alert_classifier_node)

    builder.set_entry_point("log_ingest")

    builder.add_edge("log_ingest", "sequence_analyzer")
    builder.add_edge("sequence_analyzer", "payload_inspector")
    builder.add_edge("payload_inspector", "behavior_profiler")
    builder.add_edge("behavior_profiler", "risk_aggregator")
    builder.add_edge("risk_aggregator", "alert_classifier")
    builder.add_edge("alert_classifier", END)

    return builder.compile()


# -------------------------
# SEND FINDINGS BACK TO UI
# -------------------------

graph = create_real_agentic_workflow()

def run_agent(input_data: dict, client):
    return graph.invoke({**input_data, "client": client})