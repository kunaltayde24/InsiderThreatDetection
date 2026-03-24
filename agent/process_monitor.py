import psutil
import time
import requests
import win32gui
import win32process
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import threading
import logging
from PIL import ImageGrab

# ---------------- CONFIG ---------------- #
BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "Kunal-PC"

sensitive_keywords = ["confidential", "salary", "project", "secret"]
risky_processes = ["cmd", "powershell", "mimikatz"]

WATCH_PATHS = [r"E:\Download"]

# ---------------- LOGGING ---------------- #
logging.basicConfig(
    filename="agent.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------- GLOBAL STATE ---------------- #
process_start_time = {}
active_app = None
active_start = None
event_queue = []
file_access_count = 0

# ---------------- LOCATION ---------------- #
def get_location():
    try:
        res = requests.get("https://ipinfo.io/json", timeout=2).json()
        return res.get("city", "Unknown")
    except:
        return "Unknown"

LOCATION = get_location()

# ---------------- SCREENSHOT ---------------- #
# def capture_screen(reason="event"):
#     try:
#         os.makedirs("screenshots", exist_ok=True)
#         path = f"screenshots/{int(time.time())}_{reason}.png"
#         img = ImageGrab.grab()
#         img.save(path)
#         logging.info(f"Screenshot captured: {path}")
#     except Exception as e:
#         logging.error(f"Screenshot error: {e}")

# ---------------- EVENT HANDLING ---------------- #
def add_event(data):
    global event_queue
    event_queue.append(data)

def send_event_batch():
    global event_queue
    if not event_queue:
        return

    try:
        print(f"🚀 Sending {len(event_queue)} events")   # DEBUG
        requests.post(BACKEND_URL, json=event_queue, timeout=3)
        logging.info(f"Sent {len(event_queue)} events")
        event_queue = []
    except Exception as e:
        logging.error(f"Backend error: {e}")
        with open("offline_events.log", "a") as f:
            f.write(str(event_queue) + "\n")
        event_queue = []

# ---------------- FOREGROUND APP ---------------- #
def get_foreground_process():
    try:
        hwnd = win32gui.GetForegroundWindow()
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        proc = psutil.Process(pid)
        return proc.name(), pid
    except:
        return None, None

# ---------------- RISK DETECTION ---------------- #
def is_suspicious_process(name):
    name = name.lower()
    return any(risk in name for risk in risky_processes)

def calculate_risk(event):
    risk = 0

    if event.get("file_sensitive"):
        risk += 30

    if event.get("malicious_process"):
        risk += 50

    hour = datetime.now().hour
    if hour < 6 or hour > 22:
        risk += 20

    return min(risk, 100)

# ---------------- FILE TRACKING ---------------- #
class FileAccessHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            handle_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            handle_file(event.src_path)

def handle_file(file_path):
    global file_access_count

    try:
        file_access_count += 1

        print("📂 FILE DETECTED:", file_path)  # DEBUG

        is_sensitive = any(word in file_path.lower() for word in sensitive_keywords)

        event = {
            "user_id": USER_ID,
            "action": "file_access",
            "file_path": file_path,
            "file_sensitive": is_sensitive,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "location": LOCATION
        }

        event["risk_score"] = calculate_risk(event)

        if is_sensitive:
            capture_screen("sensitive_file")

        if file_access_count > 15:
            logging.warning("High file access rate detected")

        add_event(event)

        # 🔥 FIX: SEND IMMEDIATELY
        send_event_batch()

    except Exception as e:
        logging.error(f"File tracking error: {e}")

# ---------------- WATCHDOG ---------------- #
def start_file_watcher():
    observer = Observer()

    for path in WATCH_PATHS:
        if os.path.exists(path):
            logging.info(f"Watching: {path}")
            observer.schedule(FileAccessHandler(), path=path, recursive=True)
        else:
            logging.warning(f"Path not found: {path}")

    observer.start()
    observer.join()

# ---------------- MAIN MONITOR ---------------- #
def monitor_system():
    global active_app, active_start

    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()

            # -------- Foreground App -------- #
            proc_name, pid = get_foreground_process()

            if proc_name != active_app:
                if active_app:
                    duration = time.time() - active_start

                    event = {
                        "user_id": USER_ID,
                        "action": "app_usage",
                        "app_name": active_app,
                        "duration_sec": round(duration, 2),
                        "timestamp": now,
                        "location": LOCATION
                    }

                    event["risk_score"] = calculate_risk(event)
                    add_event(event)

                active_app = proc_name
                active_start = time.time()

                add_event({
                    "user_id": USER_ID,
                    "action": "app_open",
                    "app_name": proc_name,
                    "pid": pid,
                    "timestamp": now,
                    "location": LOCATION
                })

            # -------- Process Tracking -------- #
            current = {p.pid: p.info['name'] for p in psutil.process_iter(['pid', 'name'])}

            for pid, name in current.items():
                if pid not in process_start_time:
                    process_start_time[pid] = time.time()

                    is_malicious = is_suspicious_process(name)

                    event = {
                        "user_id": USER_ID,
                        "action": "process_start",
                        "process_name": name,
                        "pid": pid,
                        "timestamp": now,
                        "location": LOCATION,
                        "malicious_process": is_malicious
                    }

                    event["risk_score"] = calculate_risk(event)

                    if is_malicious:
                        capture_screen("malicious_process")

                    add_event(event)

            stopped = set(process_start_time.keys()) - set(current.keys())

            for pid in stopped:
                duration = time.time() - process_start_time[pid]

                add_event({
                    "user_id": USER_ID,
                    "action": "process_stop",
                    "pid": pid,
                    "duration_sec": round(duration, 2),
                    "timestamp": now,
                    "location": LOCATION
                })

                del process_start_time[pid]

            # 🔥 SEND EVERY LOOP (NO DELAY)
            send_event_batch()

            time.sleep(3)

        except Exception as e:
            logging.error(f"Monitor error: {e}")

# ---------------- START SYSTEM ---------------- #
if __name__ == "__main__":
    try:
        threading.Thread(target=start_file_watcher, daemon=True).start()
        monitor_system()

    except KeyboardInterrupt:
        logging.info("Monitoring stopped")
        send_event_batch()