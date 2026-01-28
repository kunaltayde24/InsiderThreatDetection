import time
import requests
import random
from datetime import datetime
from threading import Thread

# -------------------------------
# Optional: file monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------------------------------
# Optional: process monitoring
import psutil

# -------------------------------
# Optional: keyboard/mouse activity
from pynput import keyboard, mouse

# -------------------------------
# Config
BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "emp_007"

# -------------------------------
# Helper functions
def is_off_hours():
    hour = datetime.now().hour
    return hour < 9 or hour > 18

def send_event(event):
    try:
        requests.post(BACKEND_URL, json=event)
        print("📡 Sent:", event)
    except Exception as e:
        print("⚠️ Failed to send:", event, e)

# -------------------------------
# 1️⃣ File monitoring
class FileAccessHandler(FileSystemEventHandler):
    def on_modified(self, event):
        self.send_event("modified_file", event.src_path)

    def on_created(self, event):
        self.send_event("created_file", event.src_path)

    def on_deleted(self, event):
        self.send_event("deleted_file", event.src_path)

    def send_event(self, action, file_path):
        event = {
            "user_id": USER_ID,
            "action": action,
            "file_path": file_path,
            "off_hours": is_off_hours()
        }
        send_event(event)

def start_file_monitor(path="C:/Users/YourUsername/Documents"):
    event_handler = FileAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# -------------------------------
# 2️⃣ Process monitoring
def start_process_monitor(interval=3):
    previous = set()
    while True:
        current = set(p.name() for p in psutil.process_iter())
        new_processes = current - previous
        stopped_processes = previous - current

        for p in new_processes:
            send_event({"user_id": USER_ID, "action": "start_process", "process_name": p, "off_hours": is_off_hours()})
        for p in stopped_processes:
            send_event({"user_id": USER_ID, "action": "stop_process", "process_name": p, "off_hours": is_off_hours()})

        previous = current
        time.sleep(interval)

# -------------------------------
# 3️⃣ Keyboard & Mouse monitoring (idle vs active)
last_activity = time.time()

def on_input(_):
    global last_activity
    last_activity = time.time()
    send_event({"user_id": USER_ID, "action": "active", "off_hours": is_off_hours()})

def start_keyboard_monitor():
    keyboard.Listener(on_press=on_input).start()
    mouse.Listener(on_click=on_input, on_move=on_input).start()
    global last_activity
    while True:
        if time.time() - last_activity > 60:  # idle if no input > 60 sec
            send_event({"user_id": USER_ID, "action": "idle", "off_hours": is_off_hours()})
            last_activity = time.time()
        time.sleep(5)

# -------------------------------
# 4️⃣ Optional: Simulated random activity
def start_simulated_activity(interval=5):
    actions = ["browse", "download", "upload", "delete"]
    while True:
        event = {
            "user_id": USER_ID,
            "action": random.choice(actions),
            "off_hours": is_off_hours()
        }
        send_event(event)
        time.sleep(interval)

# -------------------------------
# 5️⃣ Run all threads
if __name__ == "__main__":
    threads = [
        Thread(target=start_file_monitor, args=("C:/Users/YourUsername/Documents",), daemon=True),
        Thread(target=start_process_monitor, daemon=True),
        Thread(target=start_keyboard_monitor, daemon=True),
        Thread(target=start_simulated_activity, daemon=True)
    ]

    for t in threads:
        t.start()

    print("🚀 Live activity agent running...")
    while True:
        time.sleep(1)
