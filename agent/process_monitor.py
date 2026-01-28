import psutil
import time
import requests

BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "emp_007"

previous = set()

while True:
    current = set(p.name() for p in psutil.process_iter())
    new_processes = current - previous
    stopped_processes = previous - current

    for p in new_processes:
        requests.post(BACKEND_URL, json={"user_id": USER_ID, "action": "start_process", "process_name": p})

    for p in stopped_processes:
        requests.post(BACKEND_URL, json={"user_id": USER_ID, "action": "stop_process", "process_name": p})

    previous = current
    time.sleep(3)
