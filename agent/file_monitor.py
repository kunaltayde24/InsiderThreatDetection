from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import time

BACKEND_URL = "http://127.0.0.1:8000/event"
USER_ID = "emp_007"

class FileAccessHandler(FileSystemEventHandler):
    def on_modified(self, event):
        self.send_event("modified", event.src_path)

    def on_created(self, event):
        self.send_event("created", event.src_path)

    def on_deleted(self, event):
        self.send_event("deleted", event.src_path)

    def send_event(self, action, file_path):
        event = {
            "user_id": USER_ID,
            "action": f"{action}_file",
            "file_path": file_path
        }
        try:
            requests.post(BACKEND_URL, json=event)
            print("📂 File Event Sent:", event)
        except:
            pass

if __name__ == "__main__":
    path = "C:/Users/YourUsername/Documents"  # folder to monitor
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
