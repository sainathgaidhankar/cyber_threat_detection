# Cyber Threat Detection System

A Flask + machine-learning project that classifies network traffic into `normal` or attack classes using an NSL-KDD-trained Random Forest model.

This project supports 3 input modes:
1. Dashboard Raw Flow input (recommended)
2. Manual CSV/feature input
3. Wireshark/TShark ingestion (pcap or live interface)

---

## 1) Project Structure

```text
cyber_threat_detection/
+-- backend/
¦   +-- app.py
¦   +-- requirements.txt
¦   +-- model/
¦   ¦   +-- saved_model.pkl
¦   ¦   +-- label_encoder_y.pkl
¦   ¦   +-- label_encoders_X.pkl
¦   +-- sample_data/
¦   +-- utils/
¦       +-- threat_predictor.py
¦       +-- flow_feature_adapter.py
+-- collector/
¦   +-- tshark_ingest.py
¦   +-- README.md
+-- templates/
+-- static/
+-- data/
```

---

## 2) Prerequisites

- Windows 10/11
- Python 3.10+
- pip
- Wireshark (for automatic traffic ingestion)

Optional but recommended:
- Virtual environment (`.venv`)

---

## 3) First-Time Setup

Run these commands from project root:

```powershell
cd "C:\Users\chand\OneDrive\Desktop\PROJECT\Client Project\cyber_threat_detection"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\backend\requirements.txt
```

If `pip install -r` fails for any reason, install directly:

```powershell
pip install flask pandas numpy scikit-learn
```

---

## 4) Start the Backend

```powershell
cd .\backend
python .\app.py
```

Expected startup lines:
- `Model loaded successfully`
- `Dashboard: http://localhost:5000/dashboard`

If model is not loaded, see Troubleshooting section below.

---

## 5) Open and Use the Dashboard

Open:
- `http://127.0.0.1:5000/dashboard`

Recommended usage:
1. Use **Raw Flow Input**
2. Fill required fields:
   - `protocol_type`
   - `service`
   - `flag`
   - `src_bytes`
   - `dst_bytes`
3. Click **Analyze Raw Flow**

Other options:
- Use sample CSV buttons
- Paste full CSV row and click Analyze

---

## 6) API Endpoints

- `GET /` : health
- `GET /dashboard` : UI
- `GET /api/model-info` : model metadata
- `GET /api/feature-schema` : raw-flow schema + 41 feature names
- `POST /api/predict-flow` : raw-flow prediction (backend auto-generates 41 features)
- `POST /api/predict` : direct feature dict prediction
- `POST /api/submit-row` : CSV row prediction
- `GET /api/metrics` : dashboard metrics
- `GET /api/samples` : sample rows

### Example: raw-flow prediction

```powershell
curl -X POST http://127.0.0.1:5000/api/predict-flow `
  -H "Content-Type: application/json" `
  -d "{\"protocol_type\":\"tcp\",\"service\":\"http\",\"flag\":\"SF\",\"src_bytes\":500,\"dst_bytes\":200}"
```

---

## 7) Wireshark/TShark Integration (No Manual 41 Fields)

This is the main automation path.

### Step A: Install Wireshark

1. Install Wireshark (Windows installer)
2. Ensure `tshark` is installed
3. Verify:

```powershell
tshark -v
```

If not found, use explicit path in commands:
- `C:\Program Files\Wireshark\tshark.exe`

### Step B: Keep backend running

```powershell
cd "C:\Users\chand\OneDrive\Desktop\PROJECT\Client Project\cyber_threat_detection\backend"
python app.py
```

### Step C: Run collector from project root

```powershell
cd "C:\Users\chand\OneDrive\Desktop\PROJECT\Client Project\cyber_threat_detection"
python .\collector\tshark_ingest.py --tshark-bin "C:\Program Files\Wireshark\tshark.exe" --pcap "C:\Users\chand\Downloads\test_capture.pcapng"
```

You should see output like:
- `[ok] #1 pred=normal conf=...`

### Step D: Live capture mode

List interfaces:

```powershell
tshark -D
```

Run live capture (example interface `1`):

```powershell
python .\collector\tshark_ingest.py --tshark-bin "C:\Program Files\Wireshark\tshark.exe" --interface 1
```

Optional filter:

```powershell
python .\collector\tshark_ingest.py --tshark-bin "C:\Program Files\Wireshark\tshark.exe" --interface 1 --capture-filter "tcp or udp"
```

---

## 8) Troubleshooting

### A) `Model not loaded`

Cause: missing ML libraries or broken model files.

Fix:
```powershell
pip install -r .\backend\requirements.txt
```
If model files are missing, retrain:
```powershell
cd .\backend\model
python .\train_model.py
```

### B) `No module named 'sklearn'`

Cause: dependencies not installed in active venv.

Fix:
```powershell
.\.venv\Scripts\Activate.ps1
pip install scikit-learn pandas numpy flask
```

### C) `Chart is not defined` in browser console

Cause: Chart CDN blocked/unavailable.

Current behavior: dashboard now falls back to a built-in live bar graph and metrics still work.

### D) `tshark` not recognized

Use explicit binary path:

```powershell
python .\collector\tshark_ingest.py --tshark-bin "C:\Program Files\Wireshark\tshark.exe" --pcap "C:\path\file.pcapng"
```

### E) Inconsistent scikit-learn version warning

This is a warning from loading pickle trained on another sklearn version.

Options:
1. Keep current setup (usually works)
2. Retrain model in your current environment to remove warning

---

## 9) Typical Run Order (Daily Use)

1. Activate venv
2. Start backend (`backend/app.py`)
3. Open dashboard (`http://127.0.0.1:5000/dashboard`)
4. Run TShark collector (`collector/tshark_ingest.py`) in another terminal
5. Observe live predictions and attack distribution in dashboard

---

## 10) Notes

- The model is trained on NSL-KDD style features.
- Raw modern traffic is converted to this feature format using approximation logic.
- For production-grade accuracy, retrain with your own modern dataset and feature pipeline.
