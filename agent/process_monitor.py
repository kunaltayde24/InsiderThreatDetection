import psutil
import time
import requests
import win32gui
import win32process
import pythoncom
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import threading
import logging
import wmi

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

# ---------------- STATE ---------------- #
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

# ---------------- USB HELPERS ---------------- #
def get_usb_drives(c):
    drives = set()
    try:
        for disk in c.Win32_DiskDrive():
            if "USB" in str(disk.InterfaceType):
                for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for logical in partition.associators("Win32_LogicalDiskToPartition"):
                        drives.add(logical.DeviceID)
    except Exception as e:
        logging.error(f"get_usb_drives error: {e}")
    return drives

# ---------------- EVENT SYSTEM ---------------- #
def add_event(data):
    event_queue.append(data)

def send_event_batch():
    global event_queue

    if not event_queue:
        return

    try:
        response = requests.post(
            BACKEND_URL,
            json=event_queue,
            timeout=5
        )
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

# ---------------- RISK ---------------- #
def is_suspicious_process(name):
    return any(r in name.lower() for r in risky_processes)

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

# ---------------- FILE HANDLER ---------------- #
class FileAccessHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            handle_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            handle_file(event.src_path)

def handle_file(file_path):
    global file_access_count

    file_access_count += 1
    print("📂 FILE:", file_path)

    is_sensitive = any(w in file_path.lower() for w in sensitive_keywords)

    event = {
        "user_id": USER_ID,
        "action": "file_access",
        "file_path": file_path,
        "file_sensitive": is_sensitive,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "location": LOCATION
    }

    event["risk_score"] = calculate_risk(event)

    add_event(event)
    send_event_batch()

# ---------------- WATCHDOG ---------------- #
def start_file_watcher():
    observer = Observer()

    for path in WATCH_PATHS:
        if os.path.exists(path):
            print(f"👁 Watching: {path}")
            observer.schedule(FileAccessHandler(), path=path, recursive=True)
        else:
            print(f"❌ Path not found: {path}")

    observer.start()
    observer.join()

# ---------------- USB MONITOR ---------------- #
def monitor_usb():
    global usb_known_devices

    print("🔌 USB Monitor Started")

    pythoncom.CoInitialize()
    c = wmi.WMI()

    usb_known_devices = get_usb_drives(c)

    while True:
        try:
            current = get_usb_drives(c)

            new_devices = current - usb_known_devices
            removed_devices = usb_known_devices - current

            for drive in new_devices:
                print(f"\n✅ USB Device Inserted!")
                print(f"   📁 Drive  : {drive}")
                print(f"   🕐 Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   ⚠️  Risk   : Low (25)\n")

                add_event({
                    "user_id": USER_ID,
                    "action": "usb_insert",
                    "device_name": drive,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "location": LOCATION,
                    "risk_score": 25
                })

            for drive in removed_devices:
                print(f"\n❌ USB Device Removed!")
                print(f"   📁 Drive  : {drive}")
                print(f"   🕐 Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   ⚠️  Risk   : Low (15)\n")

                add_event({
                    "user_id": USER_ID,
                    "action": "usb_remove",
                    "device_name": drive,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "location": LOCATION,
                    "risk_score": 15
                })

            usb_known_devices = current

            send_event_batch()

            time.sleep(2)

        except Exception as e:
            logging.error(f"USB error: {e}")

# ---------------- SYSTEM MONITOR ---------------- #
def monitor_system():
    global active_app, active_start, process_start_time

    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()

            proc_name, pid = get_foreground_process()

            if proc_name != active_app:
                if active_app:
                    duration = time.time() - active_start

                    add_event({
                        "user_id": USER_ID,
                        "action": "app_usage",
                        "app_name": active_app,
                        "duration_sec": round(duration, 2),
                        "timestamp": now,
                        "location": LOCATION
                    })

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

            current = {p.pid: p.info["name"] for p in psutil.process_iter(["pid", "name"])}

            for pid, name in current.items():
                if pid not in process_start_time:
                    process_start_time[pid] = time.time()

                    add_event({
                        "user_id": USER_ID,
                        "action": "process_start",
                        "process_name": name,
                        "pid": pid,
                        "timestamp": now,
                        "location": LOCATION,
                        "malicious_process": is_suspicious_process(name)
                    })

            stopped = set(process_start_time) - set(current)

            for pid in stopped:
                add_event({
                    "user_id": USER_ID,
                    "action": "process_stop",
                    "pid": pid,
                    "duration_sec": round(time.time() - process_start_time[pid], 2),
                    "timestamp": now,
                    "location": LOCATION
                })

                del process_start_time[pid]

            send_event_batch()
            time.sleep(3)

        except Exception as e:
            logging.error(f"Monitor error: {e}")

# ---------------- BACKGROUND SENDER ---------------- #
def event_sender_loop():
    while True:
        send_event_batch()
        time.sleep(3)

def monitor_network():
    known_connections = set()
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            for conn in conns:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    key = (conn.raddr.ip, conn.raddr.port)
                    if key not in known_connections:
                        known_connections.add(key)
                        suspicious = conn.raddr.port in [4444, 1337, 9001]  # common RAT ports
                        add_event({
                            "user_id": USER_ID,
                            "action": "network_connection",
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "suspicious": suspicious,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "location": LOCATION,
                            "risk_score": 60 if suspicious else 5
                        })
        except Exception as e:
            logging.error(f"Network error: {e}")
        time.sleep(5)
import pyperclip

def monitor_clipboard():
    last_clip = ""
    while True:
        try:
            clip = pyperclip.paste()
            if clip != last_clip and len(clip) > 20:
                last_clip = clip
                sensitive = any(w in clip.lower() for w in sensitive_keywords)
                add_event({
                    "user_id": USER_ID,
                    "action": "clipboard_copy",
                    "content_length": len(clip),
                    "sensitive_content": sensitive,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "location": LOCATION,
                    "risk_score": 40 if sensitive else 5
                })
        except:
            pass
        time.sleep(2)
# ---------------- START ---------------- #
if __name__ == "__main__":
    print("🚀 Insider Threat Agent Starting...")

    threading.Thread(target=start_file_watcher, daemon=True).start()
    threading.Thread(target=monitor_usb, daemon=True).start()
    threading.Thread(target=event_sender_loop, daemon=True).start()
    threading.Thread(target=monitor_network, daemon=True).start()

    monitor_system()