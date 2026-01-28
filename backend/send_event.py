import requests

response = requests.post(
    "http://127.0.0.1:8000/event",
    json={
        "user_id": "emp_007",
        "action": "download",
        "off_hours": True
    }
)

print(response.status_code)
print(response.json())
