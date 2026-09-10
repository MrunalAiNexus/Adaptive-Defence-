# Research Methodology & Mathematical Modeling

## 1. Research Question
> **"Can machine-learning-based risk scoring improve cybersecurity threat detection and adaptive response compared with conventional rule-based detection?"**

### Hypotheses
* **Null Hypothesis ($H_0$)**: There is no statistically significant difference in threat detection precision, recall, and false positive rates between static rule-based detection (Snort-style) and machine-learning-based threat classification with multi-factor risk scoring.
* **Alternative Hypothesis ($H_1$)**: Machine-learning-based classification combined with continuous multi-factor risk scoring significantly improves malicious recall ($p < 0.01$), lowers false positive rates ($FPR < 2\%$), and enables automated sub-second adaptive containment.

---

## 2. Machine Learning Threat Detection Formulation

Let network event $x \in \mathbb{R}^d$ represent a normalized $d$-dimensional feature vector extracted from raw network telemetry:
$$x = [x_{\text{duration}}, x_{\text{srcBytes}}, x_{\text{dstBytes}}, x_{\text{packetCount}}, x_{\text{failedLogins}}, x_{\text{reqFreq}}, \dots]^T$$

The classification task maps feature vector $x$ to a discrete set of threat classes:
$$\mathcal{C} = \{\text{BENIGN}, \text{DOS}, \text{PROBE}, \text{BRUTE\_FORCE}, \text{BOT}, \text{WEB\_ATTACK}, \text{OTHER\_MALICIOUS}\}$$

### Model Architectures Evaluated
1. **Rule-Based Heuristic Baseline**: Deterministic boolean logic trees evaluating fixed thresholds ($\theta_{\text{fail}} \ge 3$, $\text{Flag} = \text{S0} \land \text{rate} > 150$).
2. **Logistic Regression (L2 Regularized Baseline)**:
   $$P(y = c \mid x) = \frac{\exp(w_c^T x + b_c)}{\sum_{j \in \mathcal{C}} \exp(w_j^T x + b_j)}$$
3. **Random Forest Ensemble ($B = 100$ Trees)**:
   $$P(y = c \mid x) = \frac{1}{B} \sum_{b=1}^B \mathbb{I}(T_b(x) = c)$$
   where each tree $T_b$ is trained via recursive Gini impurity minimization:
   $$I_G(p) = 1 - \sum_{k \in \mathcal{C}} p_k^2$$

---

## 3. Multi-Factor Risk Scoring Formulation

Traditional intrusion detection systems output a binary alert (`0` or `1`), resulting in catastrophic alert fatigue for Security Operations Center (SOC) analysts. This system implements a continuous **0–100 Multi-Factor Risk Scoring Engine**:

$$\text{RiskScore}(x) = \min\Big(100, \max\big(0, \mathcal{S}_{\text{ML}} + \mathcal{S}_{\text{Sev}} + \mathcal{S}_{\text{Anom}} + \mathcal{S}_{\text{Behav}} - \mathcal{M}_{\text{Benign}}\big)\Big)$$

### Mathematical Components:
1. **ML Probability Weight ($w_1 = 0.45$, max 45 pts)**:
   $$\mathcal{S}_{\text{ML}} = 100 \times w_1 \times (1 - P(y = \text{BENIGN} \mid x))$$
2. **Threat Severity Base ($w_2 = 0.25$, max 25 pts)**:
   $$\mathcal{S}_{\text{Sev}} = 100 \times w_2 \times \Omega(\hat{y})$$
   where severity scale $\Omega \in [0.05, 1.0]$ ($\text{BENIGN}=0.05$, $\text{PROBE}=0.55$, $\text{BOT}=0.85$, $\text{DOS}=0.92$).
3. **Traffic Anomaly Index ($w_3 = 0.15$, max 15 pts)**:
   $$\mathcal{S}_{\text{Anom}} = 100 \times w_3 \times \min\Big(1.0, \frac{\text{reqFreq}}{150} \times 0.6 + \mathbb{I}(\text{State} \in \{\text{S0}, \text{REJ}\}) \times 0.4\Big)$$
4. **Behavioral Anomaly Penalty ($w_4 = 0.15$, max 15 pts)**:
   $$\mathcal{S}_{\text{Behav}} = 100 \times w_4 \times \min(1.0, \text{failedLogins} \times 0.35)$$
5. **Benign Mitigation Credit ($\mathcal{M}_{\text{Benign}} = 15$ pts)**:
   $$\mathcal{M}_{\text{Benign}} = 15 \quad \text{if } \hat{y} = \text{BENIGN} \land \text{failedLogins} = 0 \land \text{State} = \text{SF}, \quad \text{else } 0$$

### Risk Tiers
* **0 – 30 (Low)**: Normal activity; log telemetry and continue passive monitoring.
* **31 – 60 (Moderate)**: Suspicious jitter or minor probe; trigger automated rolling PCAP and elevated monitoring.
* **61 – 80 (High)**: Confirmed brute force or reconnaissance; enforce token-bucket rate throttling and step-up MFA challenge.
* **81 – 100 (Critical)**: Active volumetric DoS or critical exploit; trigger immediate simulated blackhole quarantine and administrator paging.
