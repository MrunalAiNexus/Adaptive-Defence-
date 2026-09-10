# Threat Model (STRIDE Methodology)

This document analyzes the security properties of the **Threat Detection & Adaptive Cyber Defense System** itself.

## 1. System Asset Boundary
* **Data in Transit**: Network event payloads sent via REST endpoints (`/api/analyze`, `/api/analyze/csv`).
* **Data at Rest**: Telemetry history, alert logs, and threat predictions stored in the database.
* **ML Model Artifacts**: Trained weights, scalers, and decision trees in `ml/saved_models/`.
* **Adaptive Control Plane**: Simulated SOAR command execution pipeline.

---

## 2. STRIDE Threat Analysis & Mitigations

| STRIDE Category | Threat Description | Severity | Platform Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing (Identity)** | Adversary impersonates a SOC analyst to alter alert statuses or tamper with adaptive defense rules. | High | Role-Based Access Control (RBAC) with secure session authentication. Only Administrator role can revoke containment actions. |
| **Tampering (Data)** | Adversary injects malicious CSV headers or malformed payload formats to crash the inference pipeline. | High | Strict Pydantic schema validation, sanitization of numeric floats, and bounds-checking on ports (1–65535). |
| **Repudiation** | An analyst marks an active DoS incident as "False Positive" without traceability. | Medium | Audit logging of all alert state transitions, recording user ID, timestamp, and analyst notes. |
| **Information Disclosure** | Unauthorized actors read network telemetry containing private internal IP topology and port maps. | High | Scoped API responses; authenticated session tokens; no exposure of database credentials or internal secrets. |
| **Denial of Service** | Malicious actor floods `/api/analyze/csv` with gigabyte-sized files to induce memory exhaustion (OOM). | High | Maximum payload limit enforced (10MB); batch size clamped to 250 records per request with streaming parser. |
| **Elevation of Privilege** | Attacker attempts to execute arbitrary shell commands via the adaptive defense engine. | Critical | **Zero real-world command execution**: All adaptive defense actions are rendered through a strictly simulated, sandboxed SOAR model. No arbitrary shell commands or unsanitized strings are passed to `os.system` or `exec`. |
