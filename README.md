# Mini-SIEM
A Real time log analyzer and alert system 











## How to parse real logs


1. Copy your Windows Security log from:
   `C:\Windows\System32\winevt\Logs\Security.evtx`
2. Place the file inside the local `/logs` directory:
   `logs/Security.evtx`
3. Run the ingestion script:
   ```bash
   python Parse_real_logs.py