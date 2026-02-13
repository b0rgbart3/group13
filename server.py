from fastapi import FastAPI

app = FastAPI()

# Placeholder mock data — flesh this out later
MOCK_LOGS = [
    {"id": 1, "timestamp": "2026-02-13T10:00:00Z", "level": "INFO", "message": "Server started"},
    {"id": 2, "timestamp": "2026-02-13T10:01:23Z", "level": "WARNING", "message": "High memory usage detected"},
    {"id": 3, "timestamp": "2026-02-13T10:02:45Z", "level": "ERROR", "message": "Failed to connect to database"},
]


@app.get("/logs")
def get_logs():
    return MOCK_LOGS
