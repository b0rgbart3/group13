import requests

response = requests.get("http://localhost:8000/logs")
logs = response.json()

for log in logs:
    print(log)
