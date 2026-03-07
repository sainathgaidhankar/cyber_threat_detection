# Wireshark/TShark Ingestion (Windows-Friendly)

This collector removes manual 41-field entry by reading traffic from `tshark`,
building flow payloads, and calling:

- `POST /api/predict-flow`

Backend auto-generates all 41 model features.

## 1) Start backend

```powershell
cd backend
python app.py
```

## 2) Install Wireshark (includes tshark)

- Install Wireshark on Windows.
- Ensure `tshark` is available in PATH:

```powershell
tshark -v
```

If not found, add Wireshark install folder (usually `C:\Program Files\Wireshark`) to PATH.

## 3) PCAP mode (recommended first test)

From project root:

```powershell
python collector\tshark_ingest.py --pcap C:\path\to\capture.pcap
```

## 4) Live capture mode

List interfaces:

```powershell
tshark -D
```

Capture live traffic (example using interface index `1`):

```powershell
python collector\tshark_ingest.py --interface 1
```

Optional live capture filter (reduces noise):

```powershell
python collector\tshark_ingest.py --interface 1 --capture-filter "tcp or udp"
```

## Optional flags

```powershell
python collector\tshark_ingest.py `
  --pcap C:\path\to\capture.pcap `
  --api-url http://127.0.0.1:5000/api/predict-flow `
  --display-filter "ip" `
  --flow-timeout 3 `
  --flush-interval 0.5
```

## Notes

- TShark mode approximates NSL-KDD-style features from packet/flow data.
- For best prediction quality, keep backend running continuously so rate features build history.
