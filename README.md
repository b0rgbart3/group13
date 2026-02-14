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
│  Log Server  │               │  Dashboard   │                 │  (6-node pipeline)│
└─────────────┘               └──────┬───────┘                 └──────────────────┘
      ▲                               │                                │
      │                               │  OpenRouter API                │
  mock_logs.json                      └────────────────────────────────┘
```

### Agent Pipeline

The LangGraph agent processes each log entry through six sequential nodes:

```
log_ingest → sequence_analyzer → payload_inspector → behavior_profiler → risk_aggregator → alert_classifier
```

| Node                  | Purpose                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------- |
| **log_ingest**        | Ingests raw event data into agent state                                                                 |
| **sequence_analyzer** | Detects login velocity, sequential object access, request frequency, repeated actions                   |
| **payload_inspector** | Scans for SQL injection signatures, unexpected fields (isAdmin, role), command injection                |
| **behavior_profiler** | Evaluates geographic deviation, role deviation, user agent anomalies (e.g. sqlmap)                      |
| **risk_aggregator**   | Computes weighted risk score (40% sequence + 40% payload + 20% behavior)                                |
| **alert_classifier**  | Classifies threat type: `SQL_INJECTION`, `CREDENTIAL_STUFFING`, `POSSIBLE_IDOR`, `BUSINESS_LOGIC_ABUSE` |

## Project Structure

```
server.py           – FastAPI server exposing GET /logs (serves mock log data)
agent.py            – LangGraph stateful agent with SecurityState and 6 analysis nodes
main.py             – Streamlit dashboard: log viewer, agent runner, risk visualizations (bar, radar, heatmap, donut)
mock_logs.json      – 16 realistic security log entries across 6 vulnerability categories
requirements.txt    – Python dependencies
.env                – OpenRouter API key (not committed)
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

## Key Technologies

- **[FastAPI](https://fastapi.tiangolo.com/)** — REST API for log ingestion
- **[Streamlit](https://streamlit.io/)** — interactive dashboard UI
- **[LangGraph](https://langchain-ai.github.io/langgraph/)** — stateful agent workflow orchestration
- **[OpenRouter](https://openrouter.ai/)** — LLM gateway (routes to GPT-4o-mini)
- **[OpenAI SDK](https://github.com/openai/openai-python)** — client for OpenRouter API communication
- **[Pandas](https://pandas.pydata.org/)** — log data display and chart data preparation
- **[Plotly](https://plotly.com/python/)** — interactive charts (radar, grouped bar, heatmap, donut)
