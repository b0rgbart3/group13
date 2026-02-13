# AI Security Log Monitor

An AI-powered security log monitoring tool built with Streamlit, FastAPI, and LangGraph. It ingests server logs via a REST API, displays them in an interactive dashboard, and runs an autonomous LangGraph agent (backed by OpenRouter LLMs) to extract structured data and surface security insights.

# SlideDeck

https://app.chroniclehq.com/share/a9743016-68fb-4b6f-b979-491a21bde001/f320e1fa-6e0e-4488-affa-7b05d531cc6c/intro

## Architecture

```
┌─────────────┐    HTTP     ┌─────────────┐   LangGraph   ┌─────────────────┐
│  FastAPI     │ ◄────────► │  Streamlit   │ ────────────► │  Data Extraction│
│  Log Server  │   /logs    │  Dashboard   │               │  Agent          │
└─────────────┘             └─────────────┘               └─────────────────┘
                                   │                              │
                                   │  OpenRouter API              │
                                   └──────────────────────────────┘
```

## Project Structure

```
server.py         - FastAPI server exposing a /logs endpoint (mock data)
agent.py          - LangGraph agentic workflow with a DataExtractionAgent
main.py           - Streamlit UI: dashboard, sidebar config, agent runner
requirements.txt  - Python dependencies
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install streamlit openai pandas
```

> **Note:** `streamlit`, `openai`, and `pandas` are used by `main.py` but not yet listed in `requirements.txt`. Install them separately or add them to the file.

## Running

### 1. Start the FastAPI log server

```bash
source venv/bin/activate
uvicorn server:app --reload
```

The server starts at `http://localhost:8000`.

| Method | Path  | Description                           |
| ------ | ----- | ------------------------------------- |
| GET    | /logs | Returns server logs (mock data)       |
| GET    | /docs | Interactive API docs (auto-generated) |

### 2. Launch the Streamlit dashboard

In a separate terminal:

```bash
source venv/bin/activate
streamlit run main.py
```

### 3. Configure and run the agent

1. Open the Streamlit app in your browser.
2. Enter your **OpenRouter API key** in the sidebar (get one at https://openrouter.ai/keys).
3. View the fetched security logs in the main panel.
4. Click **Run Agent** to trigger the LangGraph data-extraction workflow.

## Key Technologies

- **FastAPI** - lightweight REST API for log ingestion
- **Streamlit** - interactive dashboard UI
- **LangGraph** - stateful agent workflow orchestration
- **OpenRouter** - LLM gateway (routes to GPT-4o-mini by default)
- **OpenAI SDK** - client used to communicate with OpenRouter
