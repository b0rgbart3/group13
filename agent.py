import requests
import os
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

response = requests.get("http://localhost:8000/logs")
logs = response.json()

for log in logs:
    print(log)
