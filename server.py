from fastapi import FastAPI

app = FastAPI()

import json



# Placeholder mock data — flesh this out later
MOCK_LOGS_1 = [
    {"id": 1, "timestamp": "2026-02-13T10:00:00Z", "level": "INFO", "message": "Server started"},
    {"id": 2, "timestamp": "2026-02-13T10:01:23Z", "level": "WARNING", "message": "High memory usage detected"},
    {"id": 3, "timestamp": "2026-02-13T10:02:45Z", "level": "ERROR", "message": "Failed to connect to database"},
]

with open("mock_logs.json") as MOCK_LOGS_2:
    MOCK_LOGS_2 = json.load(MOCK_LOGS_2)



@app.get("/logs")
def get_logs():
    print ("got log request")
    return MOCK_LOGS_2
