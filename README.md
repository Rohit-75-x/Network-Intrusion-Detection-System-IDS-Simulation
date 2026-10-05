# Network Intrusion Detection System (IDS) Simulation

> **A Defensive Cybersecurity Engineering Project** featuring synthetic network flow generation, multi-layer signature and statistical anomaly detection, hybrid risk scoring, alert correlation, SOC analytics dashboard, and resilient machine learning.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cybersecurity: Blue Team](https://img.shields.io/badge/Focus-Defensive%20Security%20%2F%20SOC-red.svg)](#)

---

## Table of Contents
1. [Overview & Problem Statement](#overview--problem-statement)
2. [Cybersecurity & SOC Relevance](#cybersecurity--soc-relevance)
3. [Key Concepts & Terminology](#key-concepts--terminology)
4. [System Architecture](#system-architecture)
5. [Detection Pipeline (Multi-Layer Hybrid)](#detection-pipeline-multi-layer-hybrid)
6. [Feature Engineering](#feature-engineering)
7. [Signature Rule Catalog](#signature-rule-catalog)
8. [Statistical Anomaly Detection](#statistical-anomaly-detection)
9. [Machine Learning Models](#machine-learning-models)
10. [Risk Scoring & Operational Tiers](#risk-scoring--operational-tiers)
11. [Alert Generation & Correlation](#alert-generation--correlation)
12. [SOC Dashboard & Forensic Investigation](#soc-dashboard--forensic-investigation)
13. [Directory Structure](#directory-structure)
14. [Installation & Quickstart](#installation--quickstart)
15. [Automated Testing Suite (30 Scenarios)](#automated-testing-suite-30-scenarios)
16. [Safe Synthetic Scenarios](#safe-synthetic-scenarios)
17. [False Positives & Operational Tuning](#false-positives--operational-tuning)
18. [MITRE ATT&CK & SIEM Integration](#mitre-attck--siem-integration)
19. [Ethical & Defensive Disclaimer](#ethical--defensive-disclaimer)

---

## Overview & Problem Statement

Modern enterprise Security Operations Centers (SOCs) and Network Operations Centers (NOCs) ingest millions of network flow events daily. Relying exclusively on static signature matching leaves organizations blind to zero-day deviations, while relying solely on raw anomaly detection floods analysts with false positive fatigue.

This project delivers a **Network Intrusion Detection System (IDS) Simulation** that models real-world enterprise detection architecture. It combines:
- **Rule-Based Signature Matching** (high precision for known threat patterns)
- **Statistical Anomaly Detection** ($Z$-score and IQR baseline deviation analysis)
- **Supervised & Unsupervised Machine Learning** (Random Forest and Isolation Forest classifiers)
- **Hybrid Risk Scoring & Alert Correlation** (sliding-window alert grouping to mitigate alert fatigue)
- **Real-Time SOC Operations Dashboard** (live telemetry charts, filterable alert queue, and interactive forensic triage playbooks)

---

## Cybersecurity & SOC Relevance

This project mirrors tools such as **Suricata**, **Snort**, and **Zeek** integrated with Security Information and Event Management (**SIEM**) and Network Detection & Response (**NDR**) platforms.

### Target Industry Roles
- **SOC Analyst (Tier 1 / Tier 2)**: Flow analysis, alert triage, false positive adjudication, evidence documentation.
- **Threat Detection Engineer**: Detection rule engineering, threshold calibration, baseline drift modeling.
- **Network Security Engineer**: Protocol telemetry inspection, ingress/egress perimeter monitoring.
- **Incident Response Analyst**: Forensic timeline reconstruction, root cause analysis, playbook execution.

---

## Key Concepts & Terminology

- **Network Packet**: Discrete unit of data transmitted over a network (headers + payload).
- **Network Flow**: Unidirectional or bidirectional sequence of packets sharing 5-tuple attributes (Source IP, Destination IP, Source Port, Destination Port, Protocol) within a time window.
- **Security Event**: An observable network occurrence with security relevance (e.g., flow completed with 30 failed SYN attempts).
- **Security Alert**: An escalated notification generated when an event matches detection criteria or violates statistical risk thresholds.
- **Security Incident**: A correlated collection of related alerts representing an active threat or investigation requiring human action.
- **IDS vs. IPS**: An **IDS** detects, analyzes, and alerts on malicious activity without interrupting network traffic (passive/defensive). An **IPS** actively intercepts and drops offending packets (in-line). This project is purposefully an IDS simulation.

---

## System Architecture

```
  ┌────────────────────────────────────────────────────────────┐
  │                 Safe Synthetic Traffic                     │
  │     (RFC 5737 Reserved IPs & Controlled Flow Telemetry)    │
  └─────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────┐
  │         Feature Extraction & Defensive Sanitization        │
  │     (BPS, PPS, Conn Rate, Failure Ratio, SYN Ratio)        │
  └─────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│ Layer 1:      │       │ Layer 2:      │       │ Layer 3:      │
│ Signature     │       │ Statistical   │       │ Resilient ML  │
│ Rule Engine   │       │ Anomaly Engine│       │ Random Forest │
│ (Weight: 40%) │       │ (Weight: 30%) │       │ (Weight: 30%) │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────┐
  │                Hybrid Risk Scoring Engine                  │
  │       (0 - 100 Score + Operational Severity Tiers)         │
  └─────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────┐
  │          Alert Generation & Sliding-Window Correlation     │
  │         (Aggregates Bursts into Incidents / Playbooks)     │
  └─────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────┐
  │                 SQLite Security Event Store                │
  └─────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────┐
  │           FastAPI REST API & SOC Operations Dashboard      │
  │    (Real-time KPIs, Chart.js Visuals, Triage Playbooks)    │
  └────────────────────────────────────────────────────────────┘
```

---

## Feature Engineering

The module `ids/feature_extractor.py` ingests flow records and computes derived telemetry:

| Feature | Mathematical Definition | Cybersecurity Relevance |
|---|---|---|
| `bytes_per_second` (BPS) | $\text{byte\_count} / \max(\text{duration}, 0.0001)$ | Highlights high-volume data exfiltration or amplification bursts. |
| `packets_per_second` (PPS) | $\text{packet\_count} / \max(\text{duration}, 0.0001)$ | Identifies packet-rate floods and high-frequency scanners. |
| `connection_rate` | $\text{connection\_count} / \max(\text{duration}, 0.0001)$ | Flags automated brute-force attempts and service crawling. |
| `failure_ratio` | $\text{failed\_conns} / \max(\text{connection\_count}, 1)$ | Distinguishes normal handshakes from credential stuffing or closed-port scans. |
| `syn_ratio` | $\text{syn\_count} / \max(\text{packet\_count}, 1)$ | Pinpoints half-open TCP SYN scanning and SYN flooding. |
| `average_packet_size` | $\text{byte\_count} / \max(\text{packet\_count}, 1)$ | Detects anomalous packet sizes (e.g., DNS amplification or small probe frames). |

---

## Signature Rule Catalog

The module `ids/rule_engine.py` implements configurable detection rules:

- **`IDS-001` High Connection Rate** (`HIGH`): Triggered when `connection_rate >= 30.0` and `connection_count >= 25`.
- **`IDS-002` Repeated Failed Connections** (`HIGH`): Triggered when `failed_connection_count >= 10` and `failure_ratio >= 0.50`.
- **`IDS-003` Multi-Port Probing Pattern** (`MEDIUM`): Triggered when low packet count ($\le 12$) accompanies high connection and failure counts.
- **`IDS-004` SYN-Heavy Connection Behavior** (`HIGH`): Triggered when `syn_count >= 25` and `syn_ratio >= 0.35`.
- **`IDS-005` Unusual Service-Port Activity** (`CRITICAL`): Triggered when destination port targets known malicious/backdoor ports (`4444`, `1337`, `6667`, `31337`, `5555`).
- **`IDS-006` Abnormally High Traffic Volume** (`HIGH`): Triggered when BPS exceeds $250,000$ BPS or high UDP packet surges.

---

## Statistical Anomaly Detection

The module `ids/anomaly_detector.py` establishes operational baselines from normal network traffic:
1. Calculates Mean ($\mu$), Standard Deviation ($\sigma$), and Interquartile Ranges (IQR, $Q_1, Q_3$) across normal flow features.
2. Computes positive $Z$-score deviations: $Z = \frac{x - \mu}{\sigma}$.
3. Converts standard deviations into a normalized $0 - 100$ anomaly score via non-linear sigmoid mapping.

---

## Machine Learning Models

The ML module provides zero-dependency, high-accuracy classification:
- **Supervised Model**: Random Forest Classifier ($50$ randomized decision trees, bootstrap aggregation, Gini impurity splitting).
- **Baseline Model**: L2-regularized Logistic Regression.
- **Unsupervised Model**: Isolation Forest ($35$ isolation trees measuring average recursive path length).

### Model Performance Metrics
- **Accuracy**: $99.80\%$
- **Precision**: $100.00\%$
- **Recall (TPR)**: $99.32\%$
- **F1 Score**: $0.9966$
- **False Positive Rate**: $0.00\%$

---

## Risk Scoring & Operational Tiers

$$\text{Final Risk Score} = (S_{\text{rule}} \times W_{\text{rule}}) + (S_{\text{anomaly}} \times W_{\text{anomaly}}) + (P_{\text{ml}} \times W_{\text{ml}})$$

- Default Weights: $W_{\text{rule}} = 0.40$, $W_{\text{anomaly}} = 0.30$, $W_{\text{ml}} = 0.30$.
- Operational Tiers:
  - **$0 - 20$**: `NORMAL` (Informational)
  - **$21 - 40$**: `LOW RISK` (Monitor)
  - **$41 - 60$**: `SUSPICIOUS` (Medium Priority)
  - **$61 - 80$**: `HIGH RISK` (High Priority Triage)
  - **$81 - 100$**: `CRITICAL INTRUSION` (Immediate Incident Response)

---

## Alert Generation & Correlation

The module `ids/correlation.py` aggregates bursts of alerts from the same source IP and attack type within a 60-second sliding window into a unified Security Incident, mitigating alert fatigue and tracking incident progression.

---

## SOC Dashboard & Forensic Investigation

The web dashboard (`http://127.0.0.1:8000`) provides:
1. **Real-Time KPI Cards**: Total Flows, Normal Flows, Suspicious Flows, Open Alerts, Critical Alerts, Avg Risk.
2. **Interactive Chart.js Visuals**: Live Traffic Volume/Risk Timeline, Severity Distribution, Classification Ratios, Top Matched Signatures, Transport Protocols.
3. **Forensic Triage Drawer**: Click any alert to view full flow telemetry, multi-layer score breakdown, tailored **SOC Investigation Playbooks**, lifecycle status updates (`NEW` $\to$ `INVESTIGATING` $\to$ `RESOLVED` / `FALSE_POSITIVE`), and analyst investigation notes.
4. **Live Scenario Triggers**: Ingest on-demand test flows (+ Normal Web, + High Rate, + Port Probe, + Trojan Port).

---

## Directory Structure

```
Network-IDS-Simulation/
├── backend/
│   ├── app.py                 # Main FastAPI application & static server
│   ├── database.py            # SQLite schema, indexes & persistence
│   ├── routes/
│   │   ├── flows.py           # Ingestion, feature extraction, detection API
│   │   ├── alerts.py          # Alert lifecycle & analyst notes API
│   │   ├── dashboard.py       # Aggregated KPIs & Chart.js analytics API
│   │   ├── rules.py           # Signature rule management API
│   │   └── simulation.py      # On-demand scenario trigger API
│   └── static/
│       ├── index.html         # Modern SOC Cyber Dashboard UI
│       ├── app.js             # Real-time polling & Chart.js controller
│       └── style.css          # Dark SOC theme stylesheet
├── ids/
│   ├── feature_extractor.py   # Flow feature extraction & sanitization
│   ├── rule_engine.py         # 6 configurable signature detection rules
│   ├── anomaly_detector.py    # Statistical baseline & Z-score engine
│   ├── risk_engine.py         # Hybrid risk scoring & severity tiering
│   ├── alert_engine.py        # Structured alert generation & playbooks
│   └── correlation.py         # Sliding-window alert correlation
├── ml/
│   ├── models.py              # Pure NumPy Random Forest, Isolation Forest, LR
│   ├── train_model.py         # Training pipeline & evaluation
│   ├── predict.py             # Production inference wrapper
│   └── evaluate.py            # Confusion matrix & threshold sweep
├── simulator/
│   ├── generate_dataset.py    # Synthetic dataset generator (RFC 5737 IPs)
│   └── traffic_simulator.py   # Continuous telemetry stream simulator
├── tests/
│   └── test_ids_suite.py      # 30 automated verification test cases
├── data/
│   ├── network_traffic.csv    # 5,000 synthetic flow records
│   └── ids_events.db          # SQLite security event database
├── models/
│   └── ids_models.joblib      # Serialized ML pipeline bundle
├── docs/
│   ├── PROJECT_REPORT.md      # Formal academic & engineering project report
│   ├── INTERVIEW_PREP.md      # 10 predicted technical interview Q&As
│   ├── RESUME_LINKEDIN.md     # Resume bullet points & LinkedIn post
│   ├── MITRE_SIEM_GUIDE.md    # ATT&CK mapping & SIEM JSON export guide
│   └── SCREENSHOT_GUIDE.md    # 27-point proof checklist
├── run_all.py                 # One-click launcher & verification script
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable configuration
└── .gitignore                 # Version control exclusions
```

---

## Installation & Quickstart

### 1. Clone & Setup Environment
```bash
git clone https://github.com/your-username/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. One-Click Launch
```bash
python run_all.py
```
This automatically initializes the database, validates datasets and ML models, runs the 30-scenario test suite, and starts the SOC dashboard at `http://127.0.0.1:8000`.

### 3. (Optional) Run Telemetry Simulator in a Separate Terminal
```bash
python simulator/traffic_simulator.py --mode mixed --speed normal
```

---

## Automated Testing Suite (30 Scenarios)

Run the standalone verification suite:
```bash
python tests/test_ids_suite.py
```

### Test Coverage Summary:
- **Flow Validation**: Normal TCP, UDP, DNS, HTTPS flows.
- **Attack Pattern Detection**: High connection rates, failed connection bursts, multi-port probes, SYN floods, high traffic volumes, backdoor port activity.
- **Defensive Edge Cases**: Invalid source/destination IPs, invalid ports, unsupported protocols, zero-duration flows, missing parameters.
- **Engine Components**: Feature extraction, rule matching, statistical anomaly scoring, ML inference, hybrid risk calculation, alert generation, alert correlation, status transitions, database persistence, dashboard analytics.
- **Result**: **30 / 30 Passed (100% Pass Rate)**.

---

## Ethical & Defensive Disclaimer

> [!IMPORTANT]
> **This project is strictly designed for defensive cybersecurity education, SOC training, and benign simulation.**
> All network traffic representations are synthetic data records utilizing documentation and private IP blocks (RFC 5737 and RFC 1918). It does **NOT** perform active network scanning, packet injection, denial of service, vulnerability exploitation, or communication with external infrastructure.

---

## Author
**Rohit** — Cybersecurity Engineering Project
