from pynput import keyboard, mouse
import requests
import time

BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "emp_007"

last_activity = time.time()

def on_input(_):
    global last_activity
    last_activity = time.time()
    requests.post(BACKEND_URL, json={"user_id": USER_ID, "action": "active"})

keyboard.Listener(on_press=on_input).start()
mouse.Listener(on_click=on_input, on_move=on_input).start()

while True:
    if time.time() - last_activity > 60:
        requests.post(BACKEND_URL, json={"user_id": USER_ID, "action": "idle"})
        last_activity = time.time()
    time.sleep(5)
