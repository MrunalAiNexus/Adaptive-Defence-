# AI-Powered Threat Detection & Adaptive Cyber Defense System
https://mrunal-ai-cyberdefence.ai.studio/
> An AI-driven cybersecurity platform for threat classification, continuous risk assessment, explainable security analysis, and simulated adaptive incident response.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Scikit--learn](https://img.shields.io/badge/Scikit--learn-ML-F7931E?logo=scikit-learn)](https://scikit-learn.org/)
[![Vite](https://img.shields.io/badge/Vite-Build%20Tool-646CFF?logo=vite)](https://vite.dev/)

---

## Overview

The **AI-Powered Threat Detection & Adaptive Cyber Defense System** is a cybersecurity research and development project that combines **machine learning, risk modelling, explainable AI, and SOC-style security monitoring** into a single platform.

The system analyzes network telemetry, classifies potential threats, calculates a continuous **0–100 cybersecurity risk score**, explains the factors influencing the assessment, and recommends an appropriate defensive response.

Unlike conventional rule-based detection systems that often produce binary outcomes such as *safe* or *malicious*, this project explores a **risk-aware detection model** designed to help security analysts prioritize and investigate potentially significant events.

> **Academic Context:** Major Project / Cybersecurity Research Project
> **Author:** Mrunal Urankar

---

## Key Capabilities

| Capability       | Description                                           |
| ---------------- | ----------------------------------------------------- |
| Threat Detection | Machine-learning-based network threat classification  |
| Risk Scoring     | Continuous 0–100 risk assessment                      |
| Explainable AI   | Identifies factors contributing to security decisions |
| SOC Dashboard    | Centralized security monitoring interface             |
| Alert Management | Investigation and lifecycle management                |
| Batch Analysis   | CSV-based network telemetry analysis                  |
| Forensics        | Incident investigation and analyst notes              |
| Adaptive Defense | Risk-based simulated response recommendations         |
| Research Lab     | Model comparison and experiment evaluation            |
| Dataset Analysis | NSL-KDD-based intrusion detection research            |

---

## System Workflow

```text
                    Network Telemetry
                           │
                           ▼
                Data Preprocessing
                           │
                           ▼
              ┌─────────────────────┐
              │  Machine Learning   │
              │                     │
              │ Logistic Regression │
              │    Random Forest    │
              └──────────┬──────────┘
                         │
                         ▼
                Threat Classification
                         │
                         ▼
                Multi-Factor Risk Score
                     0 ─────── 100
                         │
                         ▼
                  Explainable AI
                         │
                         ▼
               Adaptive Response Logic
                         │
                         ▼
                  SOC Dashboard
                         │
                         ▼
                 Analyst Investigation
```

---

# Machine Learning Threat Detection

The primary detection pipeline uses supervised machine learning to classify network activity into threat categories.

### Models

| Model                | Role                                |
| -------------------- | ----------------------------------- |
| Logistic Regression  | Classical machine-learning baseline |
| Random Forest        | Primary threat-classification model |
| Rule-Based Detection | Conventional detection baseline     |

### Threat Categories

The system supports classification into categories including:

```text
BENIGN
DOS
PROBE
BRUTE_FORCE
BOT
WEB_ATTACK
OTHER_MALICIOUS
```

The ML pipeline includes:

* Feature preprocessing
* Categorical feature handling
* Feature scaling where appropriate
* Model training
* Probability estimation
* Threat classification
* Confidence estimation
* Feature importance analysis
* Model evaluation

The research workflow is based primarily on the **NSL-KDD intrusion detection dataset**.

---

# Risk Scoring

Rather than treating every detected event equally, the system generates a continuous cybersecurity risk score between **0 and 100**.

The score combines multiple security indicators:

```text
Risk Score =
    ML Malicious Probability
  + Threat Severity
  + Traffic Anomaly
  + Behavioral Indicators
  - Benign Mitigation
```

The final value is constrained to:

```text
0 ≤ Risk Score ≤ 100
```

### Risk Classification

|  Score | Level    | Example Response                          |
| -----: | -------- | ----------------------------------------- |
|   0–30 | Low      | Passive monitoring                        |
|  31–60 | Moderate | Enhanced monitoring / PCAP simulation     |
|  61–80 | High     | Rate limiting / additional authentication |
| 81–100 | Critical | Simulated network isolation               |

The mathematical formulation and methodology are documented in:

```text
docs/methodology.md
```

---

# Explainable AI

The system does not rely exclusively on a raw ML prediction.

For every analyzed event, the platform can present security-relevant factors contributing to the resulting assessment.

Example:

```text
Threat Class: BRUTE_FORCE
Risk Score: 87
Risk Level: CRITICAL
Confidence: HIGH

Contributing Factors:
• Multiple failed authentication attempts
• High request frequency
• Suspicious connection behaviour

Recommended Response:
Simulated Network Isolation
```

The objective is to provide security analysts with **interpretable evidence supporting the model's assessment**, rather than presenting the prediction as an unexplained black-box result.

---

# SOC Dashboard

The frontend provides a Security Operations Center-inspired interface for monitoring and investigating security activity.

The dashboard includes:

* Threat statistics
* Risk distribution
* Network telemetry
* Security alerts
* Threat classifications
* Risk scores
* Model performance
* Incident investigation
* Adaptive defense recommendations
* Research experiments
* Dataset analysis

The interface is designed to demonstrate how ML-generated security information could be presented to a SOC analyst.

---

# Security Alert & Forensic Investigation

Detected events can be converted into security alerts and investigated through the platform.

Analysts can:

* Review detected events
* Filter alerts
* Inspect threat classifications
* Examine risk scores
* Review contributing factors
* Add investigation notes
* Update alert status
* Review recommended responses

### Example Alert Lifecycle

```text
OPEN
  │
  ▼
INVESTIGATING
  │
  ▼
MITIGATED
```

Alternatively:

```text
OPEN
  │
  ▼
FALSE POSITIVE
```

This provides a simplified representation of an incident-management workflow.

---

# Adaptive Defense Simulation

The project demonstrates a closed-loop response architecture inspired by **SOAR (Security Orchestration, Automation and Response)** concepts.

```text
Network Event
     │
     ▼
Threat Detection
     │
     ▼
Risk Assessment
     │
     ▼
Threat Severity
     │
     ▼
Response Recommendation
     │
     ▼
SOC Analyst Review
```

Depending on the calculated risk level, the platform can recommend simulated actions such as:

| Risk          | Simulated Action                     |
| ------------- | ------------------------------------ |
| Low           | Passive monitoring                   |
| Moderate      | Increased telemetry collection       |
| Moderate/High | PCAP capture simulation              |
| High          | Rate throttling                      |
| High          | Step-up authentication               |
| Critical      | Host quarantine/isolation simulation |

### Safety Boundary

All defensive actions are **simulation-only**.

The application does not:

* Modify real firewall configurations
* Isolate real hosts
* Execute destructive commands
* Automatically disable network interfaces
* Execute arbitrary shell commands

This allows adaptive-defense concepts to be demonstrated in a controlled academic environment.

---

# Research & Evaluation

A dedicated research module allows different detection strategies to be compared.

### Evaluation Approaches

```text
Rule-Based Detection
        │
        ├──────────────┐
        ▼              ▼
Logistic Regression   Random Forest
        │              │
        └──────┬───────┘
               ▼
        Comparative Analysis
```

### Evaluation Metrics

The research workflow can evaluate:

* Accuracy
* Precision
* Recall
* F1-score
* False-positive rate
* Confusion matrix
* ROC-AUC
* Model latency
* Risk-score calibration
* Response prioritization

The objective is to investigate whether combining **ML classification with continuous risk scoring** can improve security-event prioritization compared with conventional rule-based approaches.

---

# Batch CSV Analysis

Security analysts can upload network telemetry datasets and perform batch analysis.

The batch-analysis pipeline supports:

```text
CSV Upload
    ↓
Data Validation
    ↓
Feature Processing
    ↓
Threat Classification
    ↓
Risk Scoring
    ↓
Alert Generation
    ↓
Result Visualization
```

This allows larger collections of network events to be analyzed without manually submitting individual records.

A sample dataset is included for controlled experimentation.

---

# Example Analysis

A telemetry record can contain information such as:

```json
{
  "sourceIp": "192.168.1.105",
  "destinationIp": "10.0.0.5",
  "protocol": "TCP",
  "service": "HTTP",
  "srcBytes": 120,
  "dstBytes": 0,
  "duration": 0.2,
  "packetCount": 450,
  "failedLoginAttempts": 3,
  "requestFrequency": 220
}
```

The system can transform this telemetry into a security assessment such as:

```text
Threat Class : BRUTE_FORCE
Risk Score   : 87
Risk Level   : CRITICAL
Confidence   : HIGH

Recommended Action:
Simulated Network Isolation
```

---

# Architecture

```text
┌────────────────────────────────────────────┐
│          Network Telemetry / CSV            │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│       Data Preprocessing & Validation       │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│          Machine Learning Layer             │
│                                             │
│       Logistic Regression + Random Forest  │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│             Threat Classification           │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│            Multi-Factor Risk Engine         │
│                  0 – 100                    │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│             Explainable AI Layer            │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│          Adaptive Defense Simulation        │
└──────────────────────┬─────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────┐
│             SOC Analyst Dashboard           │
└────────────────────────────────────────────┘
```

---

# Technology Stack

### Frontend

* React 19
* TypeScript
* Tailwind CSS
* Vite
* Recharts
* Lucide React
* Motion

### Backend

* Node.js
* Express
* TypeScript
* Python
* FastAPI
* Uvicorn
* Pydantic

### Machine Learning

* Python
* Scikit-learn
* NumPy
* Pandas
* Joblib

### Cybersecurity Research

* NSL-KDD
* Network intrusion detection features
* Threat classification
* Risk modelling
* Statistical evaluation

### Development

* Git
* GitHub
* npm
* REST APIs

---

# Project Structure

```text
.
├── backend/
│   ├── app/
│   │   └── main.py
│   └── requirements.txt
│
├── docs/
│   ├── dissertation-guide.md
│   ├── methodology.md
│   └── threat-model.md
│
├── ml/
│   ├── data/
│   │   └── README.md
│   ├── preprocessing/
│   │   └── preprocess.py
│   ├── training/
│   │   └── train_models.py
│   └── evaluation/
│       └── evaluate.py
│
├── src/
│   ├── components/
│   │   ├── AdaptiveDefenseView.tsx
│   │   ├── AlertsView.tsx
│   │   ├── AnalyzerView.tsx
│   │   ├── DashboardView.tsx
│   │   ├── DissertationReaderView.tsx
│   │   ├── ForensicsView.tsx
│   │   ├── LabEntryPage.tsx
│   │   ├── Navbar.tsx
│   │   └── ResearchModelView.tsx
│   │
│   ├── database/
│   │   └── store.ts
│   │
│   ├── lib/
│   │   ├── mlEngine.ts
│   │   └── sampleDatasets.ts
│   │
│   ├── types.ts
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css
│
├── server.ts
├── package.json
├── vite.config.ts
├── tsconfig.json
└── README.md
```

---

# Installation

## Prerequisites

Install the following:

* Node.js 20+
* npm 9+
* Python 3.10+

Python is required for the ML and FastAPI components.

## 1. Clone the Repository

```bash

cd YOUR-REPOSITORY
```

## 2. Install Node Dependencies

```bash
npm install
```

## 3. Configure Environment Variables

Create a `.env` file based on the provided example:

```text
.env.example
```

Configure any required API or optional AI-integration variables.

## 4. Start the Frontend / Node Application

```bash
npm run dev
```

The development server will start on the configured local port.

---

# Running the FastAPI Backend

Navigate to the backend:

```bash
cd backend
```

Create a Python virtual environment.

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the API:

```bash
uvicorn app.main:app --reload --port 8000
```

FastAPI's interactive API documentation is available at:

```text
http://localhost:8000/docs
```

---

# Training the ML Models

Install the required ML dependencies:

```bash
pip install scikit-learn pandas numpy joblib
```

Run the training pipeline:

```bash
python -m ml.training.train_models
```

The training workflow compares:

```text
Logistic Regression
        vs
Random Forest
```

The resulting models can then be evaluated using the project's evaluation pipeline.

---

# API Reference

| Method  | Endpoint                    | Purpose                       |
| ------- | --------------------------- | ----------------------------- |
| `GET`   | `/api/health`               | Backend health check          |
| `GET`   | `/api/dashboard`            | Dashboard metrics             |
| `POST`  | `/api/analyze`              | Analyze network telemetry     |
| `POST`  | `/api/batch-analyze`        | Analyze multiple events       |
| `GET`   | `/api/telemetry`            | Retrieve telemetry            |
| `GET`   | `/api/alerts`               | Retrieve security alerts      |
| `PATCH` | `/api/alerts/:id`           | Update an alert               |
| `GET`   | `/api/defense/actions`      | View simulated responses      |
| `POST`  | `/api/defense/respond`      | Trigger a simulated response  |
| `GET`   | `/api/research/benchmarks`  | Retrieve model benchmarks     |
| `GET`   | `/api/research/experiments` | Retrieve research experiments |
| `POST`  | `/api/reset`                | Reset simulation data         |

---

# Research Question

> **Can machine-learning-based risk scoring improve cybersecurity threat detection and adaptive response compared with conventional rule-based detection?**

### Hypothesis

The project investigates whether combining machine-learning classification with continuous risk scoring can:

* Improve threat detection
* Reduce false positives
* Reduce alert fatigue
* Improve incident prioritization
* Provide more interpretable security assessments
* Support faster and more appropriate response recommendations

---

# Threat Model

The security analysis incorporates threat-modelling concepts, including **STRIDE**, to identify potential threats affecting the application and its components.

Detailed analysis is available in:

```text
docs/threat-model.md
```

---

# Ethical & Security Considerations

This project is intended for **academic research, controlled laboratory environments, and authorized cybersecurity demonstrations**.

The project follows a simulation-first approach for adaptive defense.

No real-world systems should be tested without explicit authorization.

The application does not intentionally provide autonomous mechanisms for real-world network disruption or destructive activity.

---

# Documentation

Additional documentation is available in the `docs/` directory.

| Document                | Description                                       |
| ----------------------- | ------------------------------------------------- |
| `methodology.md`        | Research methodology and risk-scoring formulation |
| `threat-model.md`       | STRIDE-based threat analysis                      |
| `dissertation-guide.md` | Dissertation and experiment guidance              |
| `ml/data/README.md`     | Dataset information and preparation               |

---

# Future Development

Potential future improvements include:

* Real-time network packet integration
* Streaming telemetry
* Additional intrusion-detection datasets
* Deep-learning detection models
* SHAP-based explainability
* Automated model retraining
* Improved risk-score calibration
* Production-grade authentication and authorization
* PostgreSQL/Oracle production database integration
* Cloud deployment
* SIEM integration
* MITRE ATT&CK technique mapping
* Real-time security-event ingestion
* Advanced SOC workflow automation

---

# Academic Significance

This project brings together several areas of computer science and cybersecurity:

```text
Artificial Intelligence
        +
Machine Learning
        +
Cybersecurity
        +
Risk Modelling
        +
Explainable AI
        +
Full-Stack Development
        +
Security Operations
        +
Research Methodology
```

The implementation demonstrates practical experience with:

* Machine-learning classification
* Feature engineering
* Risk modelling
* REST API development
* React and TypeScript
* Python backend development
* Security monitoring
* SOC concepts
* Explainable AI
* Dataset analysis
* Model evaluation
* Security research

---

# Author

## Mrunal Urankar

Computer Science student and cybersecurity-focused developer.

**Areas of interest**

* Cybersecurity
* Artificial Intelligence
* Machine Learning
* Security Operations
* Full-Stack Development
* Software Engineering

---

# Project Motivation

Modern security environments generate large volumes of telemetry and alerts. A detection system that treats every alert equally can make prioritization difficult for analysts.

This project explores an alternative approach: combining **machine-learning threat classification, continuous risk scoring, explainable security analysis, and simulated adaptive response** within a unified SOC-style platform.

The goal is not simply to identify whether an event is malicious, but to provide additional context around:

```text
What happened?
      ↓
How suspicious is it?
      ↓
Why was it considered suspicious?
      ↓
How severe is the risk?
      ↓
What response should be considered?
```

---

# License

This project was developed for academic and educational purposes.


