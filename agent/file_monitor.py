from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import time
import os

BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "emp_007"

# ✅ Folder to monitor (must exist)
PATH_TO_WATCH = r"E:\BE\monitor_test"
os.makedirs(PATH_TO_WATCH, exist_ok=True)

class FileAccessHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            self.send_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.send_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.send_event("deleted", event.src_path)

    def send_event(self, action, file_path):
        payload = {
            "user_id": USER_ID,
            "action": f"{action}_file",
            "file_path": file_path
        }

        try:
            requests.post(BACKEND_URL, json=payload, timeout=2)
            print("📂 File Event Sent:", payload)
        except Exception as e:
            print("❌ Backend not reachable:", e)

if __name__ == "__main__":
    event_handler = FileAccessHandler()
    observer = Observer()
    observer.schedule(event_handler, PATH_TO_WATCH, recursive=True)

    print(f"👀 Monitoring folder: {PATH_TO_WATCH}")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
