# Project Guardian 2.0 — Real-time PII Defense

This repo contains a rule-based **PII detector & redactor** and a deployment plan for placing it at an API gateway/sidecar.

## How to run
```bash
python3 detector_full_candidate_name.py iscp_pii_dataset.csv

windows (powershell)
cd C:\path\to\project-guardian-pii-defense
python.exe .\detector_full_candidate_name.py .\iscp_pii_dataset.csv

mac/linux
cd /path/to/project-guardian-pii-defense
python3 detector_full_candidate_name.py iscp_pii_dataset.csv
