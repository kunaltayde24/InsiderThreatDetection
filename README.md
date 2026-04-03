<!-- Running the Project
Start Backend (FastAPI)
uvicorn backend.main:app --reload

Backend will run on:
http://127.0.0.1:8000

Run ml model 
cd ml
python train_model.py

Run Process Monitoring
cd agent
Python process_monitor.py

Start Dashboard (Streamlit)
Open new terminal:

cd dashboard
streamlit run app.py

Dashboard runs on:
http://localhost:8501 -->


<!-- Paylod for Postman:

✅ POST Request Setup
URL:
http://127.0.0.1:8000/event

🔥 Test Payload (HIGH RISK → will trigger email)
{
  "user_id": "kunal",
  "action": "file_access",
  "file_sensitive": true,
  "malicious_process": true,
  "duration_sec": 1,
  "file_path": "C:/Users/Kunal/Desktop/secret.txt",
  "timestamp": "2026-04-03 20:30:00"
}
🟡 Medium Risk Payload (for testing levels)
{
  "user_id": "kunal",
  "action": "file_access",
  "file_sensitive": true,
  "malicious_process": false,
  "duration_sec": 5,
  "file_path": "C:/Users/Kunal/Documents/data.txt",
  "timestamp": "2026-04-03 20:32:00"
}
🟢 Low Risk Payload
{
  "user_id": "kunal",
  "action": "normal_activity",
  "file_sensitive": false,
  "malicious_process": false,
  "duration_sec": 10,
  "file_path": "C:/Users/Kunal/Documents/notes.txt",
  "timestamp": "2026-04-03 20:35:00"
} -->
