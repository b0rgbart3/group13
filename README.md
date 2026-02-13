# Security Log API and AI Agent

A lightweight FastAPI server that exposes a server logs endpoint, paired with a Python agent that consumes it.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the Server

```bash
source venv/bin/activate
uvicorn server:app --reload
```

The server starts at `http://localhost:8000`.

## Endpoints

| Method | Path  | Description                           |
| ------ | ----- | ------------------------------------- |
| GET    | /logs | Returns server logs (mock data)       |
| GET    | /docs | Interactive API docs (auto-generated) |

## Running the Agent

With the server running, open a separate terminal:

```bash
source venv/bin/activate
python agent.py
```

## Project Structure

```
server.py         - FastAPI application with /logs endpoint
agent.py          - Client that fetches logs from the server
requirements.txt  - Python dependencies
```
