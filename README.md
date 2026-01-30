<p align="center">
  <img src="banner.png" alt="RedzepTech Labs banner" width="100%" />
</p>


# RedzepTech Labs

Experimental cybersecurity research, scripts, and detection labs.

This repository contains proof-of-concept work, analysis scripts, and security research related to incident response, digital forensics, and threat detection.

---

## 🔬 Research Areas

- Incident response experimentation  
- DFIR scripting  
- Detection logic testing  
- Log analysis trials  
- Suspicious behavior analysis  

---

## 🧪 Current Labs

### LAB-01 — Suspicious Process Finder (Windows)

A quick triage helper to identify potentially suspicious running processes.

#### What it checks
- Randomized-looking process names  
- SYSTEM processes running outside System32  

#### Run
```powershell
powershell -ExecutionPolicy Bypass -File scripts/suspicious-process-finder.ps1

---

## 🧪 LAB-02 — Persistence Scanner (Windows)

Checks common persistence locations for incident response triage.

### 🔍 What it checks

- Startup registry entries  
- Scheduled tasks outside Microsoft path  
- Auto-start services outside System32  

### ▶️ How to run

```powershell
powershell -ExecutionPolicy Bypass -File scripts/persistence-scanner.ps1

---

## 🧪 LAB-03 — System Activity Timeline Builder

Creates a basic system activity timeline using event logs.

### Checks
- System boot time  
- User logons  
- Service state changes  

### Run
powershell -ExecutionPolicy Bypass -File scripts/timeline-builder.ps1

### Output
timeline.csv

---

## 🧪 LAB-04 — Suspicious Network Connection Analyzer

Analyzes active network connections and maps them to processes.

### Checks
- Non-localhost established connections  
- Process-to-connection mapping  

### Run
powershell -ExecutionPolicy Bypass -File scripts/network-connection-analyzer.ps1

### Output
suspicious_connections.csv
