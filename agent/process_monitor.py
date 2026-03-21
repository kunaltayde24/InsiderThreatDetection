import psutil
import time
import requests
import win32gui
import win32process
from datetime import datetime,timezone

BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "Kunal's Pc"

process_start_time = {}
active_app = None
active_start = None


def get_foreground_process():
    try:
        hwnd = win32gui.GetForegroundWindow()
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        proc = psutil.Process(pid)
        return proc.name(), pid
    except:
        return None, None


while True:
  
    now = datetime.now(timezone.utc).isoformat()

    # -------- Foreground app tracking --------
    proc_name, pid = get_foreground_process()

    if proc_name != active_app:
        # Close previous app session
        if active_app:
            duration = time.time() - active_start
            requests.post(BACKEND_URL, json={
                "user_id": USER_ID,
                "action": "app_usage",
                "app_name": active_app,
                "duration_sec": round(duration, 2),
                "timestamp": now
            })

        # Start new app session
        active_app = proc_name
        active_start = time.time()

        requests.post(BACKEND_URL, json={
            "user_id": USER_ID,
            "action": "app_open",
            "app_name": proc_name,
            "pid": pid,
            "timestamp": now
        })

    # -------- Process start/stop tracking --------
    current = {p.pid: p.name() for p in psutil.process_iter()}
    for pid, name in current.items():
        if pid not in process_start_time:
            process_start_time[pid] = time.time()
            requests.post(BACKEND_URL, json={
                "user_id": USER_ID,
                "action": "process_start",
                "process_name": name,
                "pid": pid,
                "timestamp": now
            })

    stopped = set(process_start_time.keys()) - set(current.keys())
    for pid in stopped:
        duration = time.time() - process_start_time[pid]
        requests.post(BACKEND_URL, json={
            "user_id": USER_ID,
            "action": "process_stop",
            "pid": pid,
            "duration_sec": round(duration, 2),
            "timestamp": now
        })
        del process_start_time[pid]

    time.sleep(2)
