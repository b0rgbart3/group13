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

    query: str | None
    analysis_mode: str | None
    priority_weights: Dict[str, float] | None
    explanation_level: str | None
    analysis_summary: Dict[str, Any] | None


# -------------------------
# NODES
# -------------------------

def intent_router_node(state: SecurityState) -> SecurityState:
    query = (state.get("query") or "").lower()

    state["analysis_mode"] = "full"
    state["priority_weights"] = {
        "sequence": 1.0,
        "payload": 1.0,
        "behavior": 1.0
    }
    state["explanation_level"] = "standard"

    if "sql" in query:
        state["analysis_mode"] = "payload_focus"
        state["priority_weights"]["payload"] = 1.5

    elif "credential" in query or "login" in query:
        state["analysis_mode"] = "sequence_focus"
        state["priority_weights"]["sequence"] = 1.5

    elif "behavior" in query:
        state["analysis_mode"] = "behavior_focus"
        state["priority_weights"]["behavior"] = 1.5

    if "explain" in query:
        state["explanation_level"] = "detailed"

    return state


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


# Combines scores from all analyzers into a single weighted risk score
# and identifies which individual factors exceeded the 0.7 threshold.
def risk_aggregator_node(state: SecurityState) -> SecurityState:
    sequence_score = max(state["sequence_features"].values())
    payload_score = max(state["payload_features"].values())
    behavior_score = max(state["behavior_features"].values())

    # Apply dynamic weights from the intent router. Base weights (0.4/0.4/0.2)
    # are scaled by priority multipliers so query-relevant categories score higher.
    weights = state["priority_weights"]

    sequence_weight = 0.4 * weights["sequence"]
    payload_weight = 0.4 * weights["payload"]
    behavior_weight = 0.2 * weights["behavior"]

    state["risk_score"] = (
        sequence_weight * sequence_score +
        payload_weight * payload_score +
        behavior_weight * behavior_score
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


# Generates candidate attack hypotheses from feature scores, evaluates
# supporting/contradicting evidence for each, and selects the strongest match.
def mini_agent_classifier_node(state: SecurityState) -> SecurityState:
    sf = state["sequence_features"]
    pf = state["payload_features"]
    bf = state["behavior_features"]
    risk_score = state["risk_score"]

    # Map hypothesis labels to their primary and supporting signals
    hypothesis_definitions = {
        "SQL_INJECTION": {
            "primary": ("sql_injection_score", pf.get("sql_injection_score", 0)),
            "support_keys": ["unexpected_field_score", "user_agent_anomaly_score"],
            "contradict_keys": ["login_velocity", "sequential_object_access"],
        },
        "CREDENTIAL_STUFFING": {
            "primary": ("login_velocity", sf.get("login_velocity", 0)),
            "support_keys": ["request_frequency", "geo_deviation_score"],
            "contradict_keys": ["sql_injection_score", "sequential_object_access"],
        },
        "POSSIBLE_IDOR": {
            "primary": ("sequential_object_access", sf.get("sequential_object_access", 0)),
            "support_keys": ["role_deviation_score", "request_frequency"],
            "contradict_keys": ["sql_injection_score", "login_velocity"],
        },
        "BUSINESS_LOGIC_ABUSE": {
            "primary": ("repeated_action_score", sf.get("repeated_action_score", 0)),
            "support_keys": ["request_frequency", "role_deviation_score"],
            "contradict_keys": ["sql_injection_score", "login_velocity"],
        },
    }

    all_features = {**sf, **pf, **bf}

    # Evaluate each hypothesis: build evidence and compute a confidence score
    evaluated = []
    for label, defn in hypothesis_definitions.items():
        primary_name, primary_score = defn["primary"]
        if primary_score <= 0.5:
            continue

        evidence = {"support": [primary_name], "contradict": [], "score": primary_score}

        for key in defn["support_keys"]:
            val = all_features.get(key, 0)
            if val > 0.5:
                evidence["support"].append(key)
                evidence["score"] += 0.1

        for key in defn["contradict_keys"]:
            val = all_features.get(key, 0)
            if val > 0.7:
                evidence["contradict"].append(key)
                evidence["score"] -= 0.15

        evidence["score"] = max(evidence["score"], 0) * risk_score
        evaluated.append((label, evidence))

    # Select the highest-scoring hypothesis
    if not evaluated:
        state["alert_type"] = None
        state["alert_confidence"] = 0.0
        state["analysis_summary"] = {
            "selected_alert": None,
            "confidence": 0.0,
            "supporting_evidence": [],
            "contradicting_evidence": [],
        }
        return state

    evaluated.sort(key=lambda x: x[1]["score"], reverse=True)
    top_label, top_evidence = evaluated[0]

    # If top two hypotheses are within 0.1, flag as multi-vector attack
    if len(evaluated) >= 2 and abs(evaluated[0][1]["score"] - evaluated[1][1]["score"]) <= 0.1:
        top_label = "MULTI_VECTOR_ATTACK"

    state["alert_type"] = top_label
    state["alert_confidence"] = top_evidence["score"]
    state["analysis_summary"] = {
        "selected_alert": top_label,
        "confidence": top_evidence["score"],
        "supporting_evidence": top_evidence["support"],
        "contradicting_evidence": top_evidence["contradict"],
    }
    return state


# -------------------------
# GRAPH CONSTRUCTION
# -------------------------

def create_real_agentic_workflow():
    builder = StateGraph(SecurityState)

    builder.add_node("log_ingest", log_ingest_node)
    builder.add_node("intent_router", intent_router_node)
    builder.add_node("sequence_analyzer", sequence_analyzer_node)
    builder.add_node("payload_inspector", payload_inspector_node)
    builder.add_node("behavior_profiler", behavior_profiler_node)
    builder.add_node("risk_aggregator", risk_aggregator_node)
    builder.add_node("mini_agent_classifier", mini_agent_classifier_node)

    builder.set_entry_point("log_ingest")

    builder.add_edge("log_ingest", "intent_router")
    builder.add_edge("intent_router", "sequence_analyzer")
    builder.add_edge("sequence_analyzer", "payload_inspector")
    builder.add_edge("payload_inspector", "behavior_profiler")
    builder.add_edge("behavior_profiler", "risk_aggregator")
    builder.add_edge("risk_aggregator", "mini_agent_classifier")
    builder.add_edge("mini_agent_classifier", END)

    return builder.compile()


# -------------------------
# SEND FINDINGS BACK TO UI
# -------------------------

graph = create_real_agentic_workflow()

def run_agent(input_data: dict, client):
    return graph.invoke({**input_data, "client": client})