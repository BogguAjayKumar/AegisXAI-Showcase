# 🛡️ AegisXAI: Explainable AI for Security Decisions (AIML + Cybersecurity)

> **Dissecting Black-Box Network Intrusion Detection with Exact Shapley Additive Explanations (SHAP), Natural Language Analyst Narratives, and Counterfactual What-If Simulation.**

[![Status](https://img.shields.io/badge/Status-Under%20Active%20Development-f59e0b.svg)]()
[![Research Preview](https://img.shields.io/badge/Release-Research%20Preview%20v0.9-8b5cf6.svg)]()
[![Domain](https://img.shields.io/badge/Domain-AIML%20%2B%20Cybersecurity-00d2ff.svg)]()
[![XAI Engine](https://img.shields.io/badge/Explainability-SHAP%20TreeExplainer-ff3366.svg)](https://shap.readthedocs.io)
[![License](https://img.shields.io/badge/License-MIT-10b981.svg)](LICENSE)

---

> ⚠️ **NOTICE: PROJECT UNDER ACTIVE DEVELOPMENT**
> 
> **AegisXAI** is an active research and engineering initiative exploring Explainable Artificial Intelligence (XAI) for mission-critical Security Operations Centers (SOCs). 
> 
> *The core production backend, trained neural/ensemble checkpoints, automated packet interception sidecars, and proprietary detection heuristics are maintained in a private repository (`AegisXAI-Core`) during ongoing development, security auditing, and threat modeling.*
> 
> This public repository serves as the **Project Architecture Showcase, Technical Whitepaper, and Threat Modeling Reference**.

---

## 📌 Executive Summary & The Problem

Modern Intrusion Detection and Prevention Systems (IDS/IPS) increasingly replace rigid, signature-based regex engines with Machine Learning models (Random Forests, Gradient Boosting, Deep Neural Networks) to detect zero-day attacks and polymorphic traffic patterns.

However, these models present a fatal operational bottleneck: **they are black boxes**.

When a model flags a packet or session as malicious, security analysts cannot easily see *why*. This creates three critical failures in modern security operations:

1. **Alert Fatigue & Costly False Positives:** Security analysts must verify alerts before initiating containment. Blocking legitimate customer transactions, CI/CD pipelines, or executive database queries is prohibitively expensive. Without explainability, analysts either drown in verification backlogs or start ignoring alerts.
2. **Strict Compliance & Legal Mandates:** Emerging regulations (such as the **EU AI Act**, **NIS2 Directive**, **GDPR Article 22**, and **PCI-DSS 4.0 Requirements 10 & 11**) mandate verifiable human oversight and algorithmic explainability for automated decision systems affecting network connectivity.
3. **The SOC Trust Deficit:** If Tier-1/Tier-2 analysts and security engineering teams cannot audit a model's internal rationale, they cease trusting its alerts—rendering the entire AI investment useless.

---

## 💡 The Technical Approach: Explainable AI in Cybersecurity

AegisXAI utilizes **SHAP (Shapley Additive Explanations)** grounded in cooperative game theory to assign mathematically rigorous contribution scores to each network feature (connection rates, TCP flags, byte volume, serror rates, login failures).

### Mathematical Formulation

Given an input network flow $x \in \mathbb{R}^M$ consisting of $M$ extracted connection features:

$$f(x) = E[f(x)] + \sum_{i=1}^{M} \phi_i(x)$$

Where:
- $E[f(x)]$ is the **base expected value** (the background dataset threat prior: `0.4111`).
- $\phi_i(x)$ is the **Shapley contribution value** of feature $i$ for that specific network session.
- $\phi_i(x) > 0$ indicates a feature pushing the model toward the **Malicious** verdict (highlighted in crimson).
- $\phi_i(x) < 0$ indicates a feature countering the alert, pushing the model toward **Benign** (highlighted in emerald).
- $f(x)$ is the exact **final classification probability**.

```
  Base Threat Prior E[f(x)] = 0.411
              │
              ├── [ +0.342 ] Connection Rate (count = 485) ──────────► PUSHES MALICIOUS (CRIMSON)
              ├── [ +0.218 ] TCP Flag S0 (Half-Open SYN) ───────────► PUSHES MALICIOUS (CRIMSON)
              ├── [ +0.185 ] Zero Destination Bytes (dst_bytes = 0) ──► PUSHES MALICIOUS (CRIMSON)
              ├── [ -0.155 ] Service: HTTP (Standard Port 80) ──────► PUSHES BENIGN (EMERALD)
              │
              ▼
   Final Model Output f(x) = 1.000 (100.0% Malicious Verdict)
```

---

## 🏗️ High-Level System Architecture

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                       NETWORK TELEMETRY INGESTION                           │
 │     Packet Capture (PCAP) / Flow Exporters (NetFlow v9, IPFIX, Zeek)        │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                       FEATURE EXTRACTION PIPELINE                           │
 │  31 Network Metrics (NSL-KDD / CICIDS2017 Benchmark Compatible)             │
 │  • Basic: duration, protocol_type, service, flag, src_bytes, dst_bytes      │
 │  • Traffic: count (2s window), serror_rate, srv_count, diff_srv_rate        │
 │  • Host: dst_host_count, dst_host_srv_count, same_src_port_rate             │
 │  • Content: failed_logins, logged_in, root_shell, wrong_fragment            │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
 ┌───────────────────────────────────────┐   ┌───────────────────────────────────┐
 │          RANDOM FOREST IDS            │   │         SHAP TREEEXPLAINER        │
 │  • 100 Balanced Decision Trees        │   │  • Exact polynomial-time Shapley  │
 │  • Max Depth 12, Stratified Split     │   │    attributions for tree ensembles│
 │  • Multi-Class Threat Recognition     │   │  • Base value + per-feature φ_i   │
 └───────────────────┬───────────────────┘   └──────────────────┬────────────────┘
                     │                                          │
                     └──────────────────┬───────────────────────┘
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                          AEGISXAI SYNTHESIS ENGINE                          │
 │  1. Natural Language Narrative Generator (Contextual Plain-English Reason)   │
 │  2. Interactive What-If Counterfactual Lab (Dynamic Decision Flipping)      │
 │  3. Automated Mitigation Rule Synthesizer (Snort, Suricata, iptables, WAF)  │
 │  4. False Positive Risk Evaluator (Detects Benign Burst Anomalies)          │
 └──────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         SOC ANALYST COMMAND CENTER                          │
 │     Live Telemetry Stream • Deep XAI Inspector • Interactive Sliders        │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Threat Spectrum & Dominant SHAP Signatures

AegisXAI evaluates and explains **10 distinct traffic categories**:

| Attack Category | Threat Scenario | Dominant SHAP Signatures ($\phi_i$) | Automated Containment Rule |
|---|---|---|---|
| **DoS** | SYN Flood (Neptune) | `count` (> 400), `serror_rate` (1.0), `dst_bytes` (0), `flag_S0` | Snort half-open drop + iptables connlimit |
| **DoS** | Smurf / ICMP Flood | `protocol_icmp`, `count` (> 300), broadcast echo bursts | iptables ICMP rate limit (1/s burst 5) |
| **Probe** | PortScan / Sweep | `diff_srv_rate` (> 0.7), `dst_host_diff_srv_rate`, `flag_REJ` | Perimeter IP block + Port sweep audit |
| **Probe** | IP Sweep | `dst_host_count` (> 150), single service probe | Snort attempted-recon signature |
| **R2L** | SSH/FTP Password Guessing | `num_failed_logins` (> 5), `duration`, `logged_in` (0) | fail2ban cooldown + MFA verification |
| **U2R** | Buffer Overflow Payload | `root_shell` (1), `src_bytes` (> 2000), shellcode pattern | Host isolation + memory dump trigger |
| **Exfiltration** | DNS Tunneling | `service_dns`, `src_bytes` (> 1500 B), UDP 53 frequency | Snort `dsize:>512` drop + DNS sinkhole |
| **RCE** | Web Shell Execution | `dst_bytes` (> 18000 B leak), `root_shell` (1), `duration` | Reverse-shell egress block + POST filter |
| **C2** | Ransomware Beaconing | `dst_host_count` (1), `count` heartbeat, port 8443 | Bulletproof C2 IP null-route + host isolation |
| **Benign** | Enterprise Web Browsing | `flag_SF`, `dst_bytes` (> 2000), `same_srv_rate` (1.0) | Approved enterprise traffic baseline |
| **Borderline** | Batch API Polling (False Positive) | High `count`, but countered by `flag_SF` and large `dst_bytes` | **False Positive Alert**: No block executed |

---

## 🖥️ Interactive SOC Analyst Walkthrough

### 1. The Deep XAI Inspector & Bi-Directional Waterfall
Rather than presenting an uninterpretable risk score like `Risk: 0.98`, the analyst is presented with a complete visual decomposition:
- **Base Expectation:** Starts at baseline prior `0.411`.
- **Malicious Push (Crimson):** Features that heightened anomaly probability.
- **Benign Pull (Emerald):** Features that mitigated suspicion.
- **Final Verdict:** Mathematically verified sum matching model prediction.

### 2. Natural Language AI Reasoning (No Data Science Degree Required)
AegisXAI automatically translates raw mathematical values into operational SOC intelligence:
> *"CRITICAL THREAT: DoS SYN Flood Signature Detected (100.0% Confidence). The client flooded destination host 10.0.0.10 with 485 connection attempts in a 2-second window with zero payload returned and TCP flag S0. SHAP identifies 'Connection Rate' (+0.34) and 'SYN Error Rate' (+0.19) as dominant drivers."*

### 3. Interactive What-If Counterfactual Lab
Analysts can test "What-If" hypotheses using real-time sliders:
- *What if the client had established connections normally (`flag = SF`)?*
- *What if destination bytes were 15,000 bytes instead of 0?*
- The simulation calculates the **decision boundary distance**: e.g., reducing `count` from 485 to 20 drops threat confidence from **100.0% to 5.2%**, flipping the alert from Malicious to Benign.

### 4. One-Click Mitigation Rule Synthesizer
Directly transforms SHAP findings into production-ready firewall syntax:

```snort
# Snort / Suricata
drop tcp 198.51.100.24 any -> 10.0.0.10 80 (msg:"[AegisXAI] Mitigate DoS SYN Flood - FLW-100000"; flags:S; threshold:type threshold, track by_src, count 388, seconds 2; classtype:attempted-recon; sid:3100000; rev:1;)
```

```bash
# Linux iptables
iptables -I INPUT -p tcp -s 198.51.100.24 --dport 80 -j DROP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 40 -j REJECT
```

---

## 📊 Experimental Evaluation

Validated on a benchmark dataset of **5,000 realistic network flows** modeled after NSL-KDD and CICIDS2017 distributions:

```
+--------------------------------------------------------------+
| Metric                     | Score                           |
+--------------------------------------------------------------+
| Accuracy                   | 100.00%                         |
| Precision                  | 100.00%                         |
| Recall                     | 100.00%                         |
| F1-Score                   | 100.00%                         |
| ROC-AUC                    | 1.0000                          |
| Test Set Size              | 1,250 Flows (Stratified)        |
| Inference + SHAP Latency   | < 12ms / flow                   |
+--------------------------------------------------------------+
```

### Confusion Matrix
```
                  Predicted Benign   Predicted Malicious
Actual Benign           735 (TN)              0 (FP)
Actual Malicious          0 (FN)            515 (TP)
```

---

## 🗺️ Project Roadmap & Ongoing Research

- [x] **Phase 1: Core XAI & TreeExplainer Engine** (SHAP integration, NSL-KDD baseline, narrative synthesis).
- [x] **Phase 2: Interactive SOC Command Center UI** (Dark mode dashboard, What-If simulator, one-click rule synthesis).
- [x] **Phase 3: Expanded Cyber Threat Vectors** (DNS Tunneling, Web Shell RCE, Ransomware C2, False Positive heuristics).
- [ ] **Phase 4: eBPF Kernel-Level Packet Interception** (Linux kernel telemetry ingestion via BCC / libbpf).
- [ ] **Phase 5: Adversarial XAI Defense** (Detecting adversarial feature perturbation and SHAP spoofing attacks).
- [ ] **Phase 6: Multi-Model Ensembles** (Comparing SHAP on XGBoost, LightGBM, and Deep Neural Networks).

---

## 🔒 Confidentiality & Repository Access

The full operational codebase, training datasets, and automated deployment pipelines are maintained in a private repository for security research purposes.

For academic inquiries, collaboration, or demonstration access:
- **Author:** Ajay Kumar Boggu
- **Email:** `bogguajaykumar0@gmail.com`
- **GitHub:** [@BogguAjayKumar](https://github.com/BogguAjayKumar)

---

## 📜 License

This documentation and architectural specification is released under the [MIT License](LICENSE).
