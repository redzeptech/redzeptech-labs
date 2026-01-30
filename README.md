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
