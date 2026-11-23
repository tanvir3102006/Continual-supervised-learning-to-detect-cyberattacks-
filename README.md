<div align="center">

# 🛡️ ShiftShield
### Continual Cyberthreat Detection & Multi-Vector Threat Intelligence Platform

[![Java 17+](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.8%2B-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![CIC-IDS2017](https://img.shields.io/badge/Dataset-CIC--IDS2017-0052CC?style=for-the-badge&logo=databricks&logoColor=white)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-12906a?style=for-the-badge)](LICENSE)
[![Zero External Java Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External%20Java%20Jars-success?style=for-the-badge)]()

<p align="center">
  <b>A unified defense lab uniting Continual Online Intrusion Detection with an On-Demand Sandbox Threat Scanner.</b>
</p>

[Key Features](#-key-features) •
[Architecture](#-system-architecture) •
[Dashboards Overview](#-two-tier-defense-dashboards) •
[CIC-IDS2017 Benchmark](#-cic-ids2017-real-dataset-integration) •
[Quick Start](#-quick-start) •
[ML Benchmarks](#-supervised-ml-benchmark-results) •
[API Reference](#-rest-api-reference)

</div>

---

## 💡 Overview

Modern cybersecurity defenses face two major operational dilemmas:
1. **At the Network Perimeter:** When machine learning classifiers are retrained on incoming attack types, they suffer from **Catastrophic Forgetting**—overwriting previous attack profiles and leaving the network blind to older exploits.
2. **At the Endpoint / User Gateway:** Firewalls cannot prevent social engineering. Users open weaponized attachments, visit phishing sites, or fall for deceptive SMS/UPI payment fraud.

**ShiftShield** bridges both layers into one coordinated, zero-dependency platform:
* **Online Continual Network IDS:** Evaluates online learning with class-balanced reservoir replay against naive models across live streams of **24,182 real network flows** from the **CIC-IDS2017** benchmark.
* **Multi-Vector Threat Scanner:** Performs pre-execution triage of websites (headless browser sandbox), suspicious files (PE/entropy/macro checks), and message texts (compound smishing and phishing detection).
* **Supervised ML Suite:** An offline training engine benchmarking production models (Random Forest, Extra Trees, Decision Trees, Logistic Regression) on raw PCAP flow datasets.

---

## 🏛️ System Architecture

```text
                                  ShiftShield Platform (localhost:8081)
                                                     │
         ┌───────────────────────────────────────────┴───────────────────────────────────────────┐
         ▼                                                                                       ▼
  🛡️ IDS Dashboard (/)                                                                    🔍 Threat Scanner (/scanner)
  ├── Online Continual Learning Stream                                                     ├── Website & IP Sandbox
  │   ├── Softmax with Experience Replay                                                   │   ├── Headless Chrome/Edge Visual Capture (1280×900)
  │   ├── Solves Catastrophic Forgetting                                                   │   ├── Live Preview Sandbox Iframe
  │   └── Live Confusion Matrix & Class Recall                                             │   ├── 1st vs 3rd Party Infrastructure Profiling
  ├── Powered by Real CIC-IDS2017 Flows                                                    │   └── TLS Audit, Redirect Chain & Form Detection
  │   └── 24,182 Authentic Network Flows (8 Classes)                                      ├── Static File Malware Scanner (up to 25 MB)
  └── Non-Stationary Temporal Drift & Noise                                                 │   ├── PE/ELF Signatures & Shannon Entropy
                                                                                           │   └── In-Memory Archive & VBA Macro Analysis
                                                                                           └── Social Engineering & Phishing NLP Engine
                                                                                               ├── Compound Synergy Fraud Rules
                                                                                               └── UPI, Delivery Smishing & Advance-Fee Fraud
```

---

## ✨ Key Features

### 1. Continual Learning Network IDS (`/`)
* **Real Benchmark Ingestion:** Pre-loaded with **24,182 real network packet flows** from the Canadian Institute for Cybersecurity (**CIC-IDS2017**):
  - `Normal` (Monday Benign baseline)
  - `DoS` (Hulk, GoldenEye, Slowloris, Heartbleed)
  - `DDoS` (LOIC & UDP floods)
  - `PortScan` (Network mapping probes)
  - `BruteForce` (FTP-Patator, SSH-Patator)
  - `SQLInjection` (SQLi, XSS, Web Brute Force)
  - `Botnet` (ARES periodic command & control)
  - `Exfiltration` (Data exfiltration & infiltration)
* **Experience Replay Memory:** Compares an online softmax model using class-balanced reservoir rehearsal against a naive learner, demonstrating how memory replay preserves past attack detection rates during distribution shift.
* **Real-time Diagnostic Metrics:** Live tracking of Accuracy, False Alarm Rate (FPR), True Positive Rate (TPR), Per-Class Recall, and real-time confusion matrices.

### 2. Multi-Vector Threat Scanner (`/scanner`)
* **Website & IP Intelligence:**
  - Headless browser rendering with anti-automation bypass to capture actual landing pages safely.
  - Interactive mode switch between **📸 High-Resolution Screenshot** (with zoom lightbox) and **🌐 Isolated Sandbox Live Preview**.
  - Infrastructure connection breakdown: 1st-party vs. 3rd-party domains, IP chips with one-click copy, and security flags.
  - Full redirect chain inspection, TLS certificate validity auditing, and login form leak alerts.
  - Safe inspection of both public hostnames and local/private addresses (`127.0.0.1`, `10.x`, `192.168.x`).
* **Static File Pre-Execution Triage:**
  - In-memory byte analysis of files up to 25 MB without executing or opening them.
  - Shannon entropy scoring (identifying packed, encrypted, or obfuscated payloads).
  - Magic header validation (PE, ELF, PDF, ZIP, RTF) vs. extension spoofing.
  - Malicious string detection (`VirtualAlloc`, `WriteProcessMemory`, `cmd.exe /c`, `DownloadString`, `mimikatz`).
  - Inspection of ZIP and Office archives for embedded scripts and VBA macros (`vbaproject.bin`).
* **Message & Phishing Heuristic Engine:**
  - Detection of compound social engineering fraud patterns:
    - **Advance-Fee Recruitment Scams:** Offers lucrative salaries while demanding registration or security fees.
    - **Prize Bait & Credential Harvesting:** Lottery winnings conditioned on disclosing bank account or personal details.
    - **Delivery Fee Smishing:** Fake courier/postal delivery failure alerts demanding nominal payment (`Pay ₹25`) via unknown links.
    - **Accidental Transfer / UPI Reversal Fraud:** Claims of mistakenly sent funds demanding immediate reversal to an external UPI ID.
    - **Urgent Account Takeover:** High-pressure threats of suspension requiring immediate credential or KYC verification.
  - Calibrated threat scores (landing realistically in the **85–95** band for high-confidence attacks).

---

## 📊 Two-Tier Defense: Dashboards Overview

| Capability | 🛡️ IDS Dashboard (`/`) | 🔍 Threat Scanner (`/scanner`) |
| :--- | :--- | :--- |
| **Defense Layer** | Network Infrastructure / Macro | Application & Endpoint / Micro |
| **Operational Mode** | Continuous real-time flow stream | On-demand single artifact triage |
| **Target Data** | TCP/UDP connection records | Websites, uploaded files, raw text |
| **Primary Threats** | DoS, DDoS, PortScan, BruteForce, Botnets | Phishing portals, Trojans, Smishing scams |
| **Underlying Tech** | Continual Learning with Reservoir Sampling | Headless browser sandboxing, byte parsing, regex NLP |
| **Target User** | Network Administrator, SOC Analyst | End user, Incident Responder, Employee |

---

## 🔬 Supervised ML Benchmark Results

The offline training suite ([ml/train_model.py](ml/train_model.py)) was evaluated on raw network flow records from the CIC-IDS2017 benchmark (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` — **225,745 flows**):



---

## ⚡ Quick Start

### Prerequisites
* **Java 17+** (JDK installed)
* **Python 3.10+** (Python 3.12 recommended)
* **Chrome or Edge** (Optional, used for headless website screenshots)

---

### 1. Launch the ShiftShield Platform (Java)

**On Windows (PowerShell / Command Prompt):**
```powershell
# 1. Compile Java sources (Zero external dependencies)
mkdir out
javac -d out (Get-ChildItem src\ids\*.java).FullName

# 2. Start the server (binds to 8080, or 8081 if occupied)
java -cp out ids.Main 8080
```

**On Linux / macOS:**
```bash
# Compile and run
mkdir -p out
javac -d out src/ids/*.java
java -cp out ids.Main 8080
```

Open your browser:
* 🛡️ **IDS Dashboard:** [http://localhost:8081/](http://localhost:8081/)
* 🔍 **Threat Scanner:** [http://localhost:8081/scanner](http://localhost:8081/scanner)

---

### 2. Run the Machine Learning Training Pipeline (Python)

Install Python dependencies:
```powershell
py -m pip install -r requirements-ml.txt
```

Train and compare classifiers on any raw capture from the extracted CIC-IDS2017 dataset:
```powershell
# Train on DDoS capture
py ml/train_model.py --csv data/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --label Label

# Train on PortScan capture
py ml/train_model.py --csv data/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --label Label
```

Run single-flow inference against the fitted model:
```powershell
py ml/predict.py --json "{\"Destination Port\":80,\"Flow Duration\":3,\"Total Fwd Packets\":2,\"Total Backward Packets\":0,\"Total Length of Fwd Packets\":12,\"Total Length of Bwd Packets\":0}"
```

---

## 🌐 REST API Reference

The Java backend exposes an asynchronous REST API used by both dashboards and external tools:

| Endpoint | Method | Parameter | Description |
| :--- | :---: | :--- | :--- |
| `/api/state` | `GET` | — | Current IDS session state, dataset source, live accuracy, and confusion matrix. |
| `/api/start` | `GET` | `classes`, `batch`, `phase`, `lr`, `cap` | Initialize a new IDS continual learning stream session. |
| `/api/step` | `GET` | `n` (default: 1) | Step forward `n` batches through the network flow stream. |
| `/api/scan/url` | `GET` | `target=<url_or_ip>` | Queues a headless browser scan job for a website or IP address. |
| `/api/scan/status` | `GET` | `id=<scan_id>` | Polls status, TLS, redirect chain, and domain analysis of an active scan. |
| `/api/scan/shot` | `GET` | `id=<scan_id>` | Returns captured PNG screenshot of the target website. |
| `/api/scan/file` | `POST` | Binary payload (`X-Filename` header) | Performs static heuristic analysis of an uploaded file (up to 25 MB). |
| `/api/scan/text` | `POST` | Raw text in request body | Evaluates email, SMS, or message text for phishing, scams, and smishing. |

---

## 📁 Repository Structure

```text
CyberProtector/
├── src/ids/                         # Core Java Backend (Zero external jar dependencies)
│   ├── Main.java                    # REST API server & prequential evaluation loop
│   ├── DataGen.java                 # Flow provider: streams real CIC-IDS2017 flows with synthetic fallback
│   ├── Classifier.java              # Online softmax IDS with reservoir replay memory
│   ├── FileScan.java                # Static file inspection & heuristic message NLP engine
│   ├── UrlScan.java                 # Headless browser capture, TLS validation, network sandbox
│   ├── Json.java                    # High-performance JSON serializer & scoring model
│   └── Sample.java                  # Network flow record representation
│
├── web/                             # Web User Interfaces
│   ├── index.html                   # Continual Learning IDS Dashboard (canvas charts & live matrix)
│   └── scanner.html                 # Threat Scanner (Website, File, and Message inspection)
│
├── data/                            # Datasets
│   ├── cicids2017_real_flows.csv    # 24,182 curated real network flows across 8 attack classes
│   └── MachineLearningCVE/          # Full 8-day CIC-IDS2017 benchmark CSV files (~880 MB)
│
├── ml/                              # Python Machine Learning Suite
│   ├── train_model.py               # Supervised model benchmark (RF, Extra Trees, DT, Logistic Regression)
│   └── predict.py                   # CLI inference tool for trained models
│
├── models/                          # Generated Artifacts
│   ├── shiftshield_model.joblib     # Best fitted model pipeline
│   └── training_report.json         # Complete performance metrics, confusion matrix & timing report
│
├── requirements-ml.txt              # Python ML package dependencies
├── .gitignore                       # Git exclusion rules (ignores raw 880MB CSVs & cache)
└── README.md                        # Documentation
```

---

## 📚 Dataset Attribution

ShiftShield uses the **CIC-IDS2017** dataset provided by the **Canadian Institute for Cybersecurity (CIC)**, University of New Brunswick:
```bibtex
@inproceedings{sharafaldin2018toward,
  title={Toward generating a new dataset for intrusion detection and realistic performance evaluation},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Ghorbani, Ali A},
  booktitle={International Conference on Information Systems Security and Privacy},
  pages={108--116},
  year={2018}
}
```

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).

---

<div align="center">
  <sub>Built with ❤️ for advanced cybersecurity research and intrusion defense education.</sub>
</div>

```
