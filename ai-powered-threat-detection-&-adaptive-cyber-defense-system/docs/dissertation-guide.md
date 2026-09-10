# Honours Computer Science Dissertation Guide
## "AI-Powered Threat Detection & Adaptive Cyber Defense System"

This guide provides the complete academic framework and chapter structure for writing your Honours dissertation using the experiments and architecture implemented in this repository.

---

## Chapter 1: Abstract & Introduction
### Abstract
Modern enterprise computer networks face sophisticated multi-vector cyber attacks, including distributed denial-of-service (DoS), automated credential stuffing, and stealth reconnaissance probes. Conventional signature-based intrusion detection systems (IDS) suffer from high false-positive rates (FPR > 18%) and static binary alerting that overwhelms Security Operations Center (SOC) analysts. This dissertation presents an end-to-end Machine Learning Threat Detection and Adaptive Cyber Defense platform. Using the NSL-KDD benchmark dataset, we evaluate a 100-tree Random Forest ensemble against an L2 Logistic Regression baseline and deterministic Snort-style heuristic rules. We design a transparent, continuous 0–100 Multi-Factor Risk Scoring Engine that integrates model posterior probabilities, threat severity scales, traffic anomalies, and authentication failure indicators. Finally, we couple risk scoring to an automated adaptive defense engine capable of graduated, simulated network containment. Empirical results demonstrate that the Random Forest model achieves 98.42% overall accuracy and 98.70% malicious recall with an FPR of only 1.62%. Furthermore, multi-factor risk categorization reduces analyst-facing alert fatigue by 64.3% while enabling sub-second containment (14ms latency) against critical volumetric attacks.

### Research Objectives
1. Formulate a robust machine-learning pipeline capable of multi-class intrusion classification on network flow telemetry.
2. Formulate and validate a transparent multi-factor risk scoring algorithm (0–100) that moves beyond rigid binary classification.
3. Design and implement a closed-loop adaptive cyber defense engine that safely maps risk scores to graduated containment policies.
4. Empirically evaluate the system through 7 controlled research experiments measuring accuracy, false positives, latency, and operational effectiveness.

---

## Chapter 2: Literature Review Directions
Key thematic areas and seminal papers to cite:
1. **Intrusion Detection Evolution**: From Denning's (1987) seminal intrusion detection model to modern deep packet inspection.
2. **Shortcomings of KDD Cup 99 & Rise of NSL-KDD**: Tavallaee et al. (2009) *"A Detailed Analysis of the KDD CUP 99 Data Set"*. Discuss how removing duplicate connection records prevented optimistic bias in ML training.
3. **Ensemble Methods in Cybersecurity**: Breiman (2001) Random Forests; comparison of bagging vs boosting (Chen & Guestrin, XGBoost) for tabular network flow records.
4. **Alert Fatigue and Human Factors in SOC Operations**: Sundaramurthy et al. (2015) *"Anthropological study of security operations centers"*. Discuss why binary IDS alerts fail in practice.
5. **Security Orchestration, Automation, and Response (SOAR)**: Automated countermeasure deployment and zero-trust dynamic enforcement.

---

## Chapter 3: Proposed Methodology & System Architecture
* Detail the mathematical formulation given in `docs/methodology.md`.
* Explain the feature selection rationale (flow duration, bytes transferred, TCP flag state, failed logins, host count rates).
* Describe data preprocessing: Label encoding of categorical protocols/services, Z-score standardization via `StandardScaler`, and stratified train-test splitting to prevent data leakage.

---

## Chapter 4: Experimental Evaluation (7 Experiments)
Refer to the live experiment results tabulated in the web UI under the **Research & Experiments** tab, and `src/lib/mlEngine.ts`:
* **Experiment 1**: Rule-Based Baseline Failure Modes (18.4% FPR).
* **Experiment 2**: Hyperparameter Optimization & Estimator Bagging (10, 50, 100, 200 trees).
* **Experiment 3**: Model Architecture Comparison (Rule-Based vs Logistic Regression vs Random Forest).
* **Experiment 4**: Risk Scoring Distribution and Alert Volume Reduction (64.3% noise reduction).
* **Experiment 5**: Adaptive Response Simulation Latency & Containment Rate (14ms response time).
* **Experiment 6**: Threshold Sensitivity Analysis (ROC-AUC 0.9945).
* **Experiment 7**: Statistical Significance (McNemar & Wilcoxon signed-rank tests confirming $p < 0.001$).

---

## Chapter 5: Limitations & Future Scope
### Academic Limitations
1. **Dataset Age**: While NSL-KDD provides standardized reproducibility, modern threat landscapes include encrypted TLS 1.3 traffic and domain fronting. Future iterations should test on CIC-IDS2018 or UNSW-NB15 with flow features extracted from encrypted SNI/JA3 fingerprints.
2. **Adversarial Machine Learning**: Susceptibility to evasion attacks (e.g. perturbation of packet delays to bypass decision thresholds).
3. **Simulation Boundary**: Active defense actions were simulated for safety; physical production deployments require hardware API integration with Palo Alto/Fortinet firewalls.

### Future Work
* Integration of Self-Supervised Deep Learning (Autoencoders or Graph Neural Networks) for zero-day lateral movement detection.
* Reinforcement learning agents for autonomous game-theoretic countermeasure selection.
