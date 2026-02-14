# AI LangGraph Agentic Security Log Monitor

An AI-powered security log monitoring system that ingests server logs via a REST API, displays them in an interactive dashboard, and runs an autonomous LangGraph agent to detect and classify security threats in real time.

The agent pipeline analyzes request sequences, inspects payloads, and profiles user behavior to produce a weighted risk score and alert classification — all with transparent, step-by-step decision making.

![AI Security Log Monitor Dashboard](agent_screenshot.jpg)

## Agent Graph

![Agent Graph](graph_structure.jpg)

## Slide Deck

[View Presentation](https://app.chroniclehq.com/share/a9743016-68fb-4b6f-b979-491a21bde001/f320e1fa-6e0e-4488-affa-7b05d531cc6c/intro)

## Architecture

```
┌─────────────┐    GET /logs   ┌─────────────┐    run_agent()   ┌──────────────────┐
│  FastAPI     │ ◄───────────► │  Streamlit   │ ──────────────► │  LangGraph Agent │
│  Log Server  │               │  Dashboard   │                 │  (7-node pipeline)│
└─────────────┘               └──────┬───────┘                 └──────────────────┘
      ▲                               │                                │
      │                               │  OpenRouter API                │
  mock_logs.json                      └────────────────────────────────┘
```

### Agent Pipeline

The LangGraph agent processes each log entry through seven sequential nodes:

```
log_ingest → intent_router → sequence_analyzer → payload_inspector → behavior_profiler → risk_aggregator → mini_agent_classifier
```

| Node                       | Purpose                                                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **log_ingest**             | Ingests raw event data into agent state                                                                                              |
| **intent_router**          | Parses user query to set analysis mode and dynamic priority weights (e.g. boosting payload weight for SQL-related queries)            |
| **sequence_analyzer**      | Detects login velocity, sequential object access, request frequency, repeated actions                                                |
| **payload_inspector**      | Scans for SQL injection signatures, unexpected fields (isAdmin, role), command injection                                             |
| **behavior_profiler**      | Evaluates geographic deviation, role deviation, user agent anomalies (e.g. sqlmap)                                                   |
| **risk_aggregator**        | Computes weighted risk score using dynamic weights from the intent router (base: 40% sequence + 40% payload + 20% behavior)          |
| **mini_agent_classifier**  | Generates candidate attack hypotheses, evaluates supporting/contradicting evidence, and selects the strongest match. Detects `SQL_INJECTION`, `CREDENTIAL_STUFFING`, `POSSIBLE_IDOR`, `BUSINESS_LOGIC_ABUSE`, or `MULTI_VECTOR_ATTACK` when top hypotheses are close in score |

## Project Structure

```
server.py                – FastAPI server exposing GET /logs (serves mock log data)
agent.py                 – LangGraph stateful agent with SecurityState and 7 analysis nodes
main.py                  – Streamlit dashboard: log viewer, agent runner, risk visualizations (bar, radar, heatmap, donut)
test_risk_aggregator.py  – Pytest suite for the risk_aggregator node (weighted scoring, dynamic weights, edge cases)
mock_logs.json           – 16 realistic security log entries across 6 vulnerability categories
requirements.txt         – Python dependencies
.env                     – OpenRouter API key (not committed)
```

## Threat Coverage

The mock dataset and agent detect the following attack patterns:

- **Credential Stuffing** — rapid failed login attempts from the same IP
- **IDOR (Insecure Direct Object Reference)** — user accessing other users' resources via sequential IDs
- **SQL Injection** — `OR 1=1`, `UNION SELECT` payloads, sqlmap user agent
- **Mass Assignment** — injecting `isAdmin` or `role` fields in request bodies
- **Business Logic Abuse** — replaying promo codes or order actions
- **API Scraping** — high-volume data extraction with large limits and bot user agents

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install streamlit openai pandas plotly
```

> **Note:** `streamlit`, `openai`, `pandas`, and `plotly` are required by `main.py` but not yet listed in `requirements.txt`.

Create a `.env` file with your API key (optional — you can also enter it in the UI):

```
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

## Running

### 1. Start the FastAPI log server

```bash
uvicorn server:app --reload
```

Runs at `http://localhost:8000`.

| Method | Path  | Description                    |
| ------ | ----- | ------------------------------ |
| GET    | /logs | Returns mock security log data |
| GET    | /docs | Interactive Swagger API docs   |

### 2. Launch the Streamlit dashboard

In a separate terminal:

```bash
streamlit run main.py
```

Opens at `http://localhost:8501`.

### 3. Analyze logs

1. Open the Streamlit app in your browser.
2. Enter your **OpenRouter API key** in the sidebar (or load from `.env`). Get one at [openrouter.ai/keys](https://openrouter.ai/keys).
3. Select a **vulnerability type** from the dropdown to view its log entries.
4. Click **Run Agent** to trigger the analysis pipeline.
5. Review the results:
   - **Risk score** with color-coded severity indicator
   - **Alert classification** and confidence level
   - **Risk factors** flagged by the agent
   - **Feature score bar chart** for all individual features
   - **Radar chart** showing max threat score per category (Sequence, Payload, Behavior)
   - **Grouped bar chart** comparing features within each category
   - **Heatmap** of all feature scores across categories
   - **Donut chart** showing weighted risk contribution by category

## Tests

The project includes a pytest suite in `test_risk_aggregator.py` that validates the `risk_aggregator` node — the component responsible for combining feature scores from all three analyzers into a final weighted risk score.

```bash
pytest test_risk_aggregator.py -v
```

| Test class                     | What it covers                                                                                        |
| ------------------------------ | ----------------------------------------------------------------------------------------------------- |
| **TestDefaultWeights**         | Verifies risk score calculation and risk factor detection with uniform (1.0) priority weights          |
| **TestPayloadBoostedWeights**  | Confirms that a payload priority multiplier of 1.5 (set by intent_router for SQL queries) increases the score relative to baseline |
| **TestSequenceBoostedWeights** | Confirms that a sequence priority multiplier of 1.5 (set by intent_router for credential/login queries) increases the score relative to baseline |
| **TestBehaviorBoostedWeights** | Confirms that a behavior priority multiplier of 1.5 increases the score relative to baseline          |
| **TestEdgeCases**              | All-zero scores, all-max scores, and boundary testing around the 0.7 risk factor threshold            |

## Key Technologies

- **[FastAPI](https://fastapi.tiangolo.com/)** — REST API for log ingestion
- **[Streamlit](https://streamlit.io/)** — interactive dashboard UI
- **[LangGraph](https://langchain-ai.github.io/langgraph/)** — stateful agent workflow orchestration
- **[OpenRouter](https://openrouter.ai/)** — LLM gateway (routes to GPT-4o-mini)
- **[OpenAI SDK](https://github.com/openai/openai-python)** — client for OpenRouter API communication
- **[Pandas](https://pandas.pydata.org/)** — log data display and chart data preparation
- **[Plotly](https://plotly.com/python/)** — interactive charts (radar, grouped bar, heatmap, donut)
