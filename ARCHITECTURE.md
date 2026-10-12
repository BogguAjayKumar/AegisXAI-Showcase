# 🏛️ AegisXAI: Technical Architecture & Theoretical Deep-Dive

> **In-depth architectural analysis of Explainable Artificial Intelligence applied to Network Intrusion Detection.**

---

## 1. The Explainability Gap in Modern Cybersecurity

Signature-based IDS systems (Snort, Suricata, Zeek) use deterministic pattern matching on packet payloads and headers:
```
alert tcp any any -> $HTTP_SERVERS 80 (msg:"Directory Traversal"; content:"/../.."; sid:1001;)
```
While explainable by definition, signature systems cannot detect novel zero-day attacks, obfuscated shellcode, or subtle rate anomalies.

Machine Learning classifiers (Random Forests, Gradient Boosting, Deep Neural Networks) solve this by learning non-linear manifolds across high-dimensional feature spaces. However, their decision logic is distributed across hundreds of decision trees or millions of weights:

```
f(x) = \frac{1}{B} \sum_{b=1}^{B} T_b(x)
```

Without an explainability layer, security analysts are forced to make a binary guess: trust the black box and risk blocking mission-critical traffic, or ignore the alert and risk a catastrophic breach.

---

## 2. Shapley Additive Explanations (SHAP) in IDS

SHAP attributes output credit to features based on classical cooperative game theory (Lloyd Shapley, 1953). In our security model:
- **Game:** The ML classification of a network connection.
- **Players:** The 31 network flow features ($x_1, x_2, \dots, x_M$).
- **Payout:** The difference between the model's actual malicious probability $f(x)$ and the base prior expectation $E[f(x)]$.

The unique Shapley value $\phi_i$ for feature $i$ is mathematically computed as:

$$\phi_i = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$

### Why SHAP over LIME for Cybersecurity?
1. **Efficiency & Exact Additivity:** $\sum_{i=1}^M \phi_i = f(x) - E[f(x)]$. The feature contributions sum up with exact arithmetic precision to the model output. LIME uses local linear approximations which can hallucinate contradictory attributions on boundary cases.
2. **Consistency (Monotonicity):** If a model is tuned such that a feature's presence increases malicious risk even more, that feature's SHAP value is guaranteed not to decrease.
3. **Polynomial TreeExplainer Speed:** For tree ensembles, `shap.TreeExplainer` calculates exact Shapley values in $\mathcal{O}(T \cdot L \cdot D^2)$ time (where $T$ is trees, $L$ is leaves, $D$ is depth), enabling real-time packet flow inspection (< 12ms).

---

## 3. Extracted Network Features (NSL-KDD / CICIDS2017)

AegisXAI tracks 31 features grouped into four operational tiers:

### Tier 1: Connection Basics
- `duration`: Length of connection in seconds.
- `protocol_type`: Protocol (`tcp`, `udp`, `icmp`).
- `service`: Target network service (`http`, `ssh`, `dns`, `ftp`, `smtp`, `private`, `other`).
- `flag`: Connection state flag (`SF` established/normal, `S0` SYN flood no ACK, `REJ` rejected, `RSTO` reset).
- `src_bytes`: Bytes transmitted from source host.
- `dst_bytes`: Bytes returned from target server.

### Tier 2: 2-Second Temporal Traffic Metrics
- `count`: Number of connections to the same destination IP in past 2 seconds.
- `srv_count`: Number of connections to the same target service in past 2 seconds.
- `serror_rate`: Ratio of connections with SYN errors (`S0`).
- `srv_serror_rate`: Ratio of connections to the same service with SYN errors.
- `same_srv_rate`: Percentage of connections targeting the same service.
- `diff_srv_rate`: Percentage of connections targeting distinct services (Key PortScan indicator).

### Tier 3: Host-Based Historical Accumulators
- `dst_host_count`: Aggregated historical connections to destination host (100-connection window).
- `dst_host_srv_count`: Aggregated historical connections to service on destination.
- `dst_host_same_srv_rate`: Ratio of same-service connections in host history.
- `dst_host_diff_srv_rate`: Ratio of distinct-service connections in host history.
- `dst_host_same_src_port_rate`: Rate of connections originating from the same source port.
- `dst_host_serror_rate`: Destination host SYN error rate.

### Tier 4: Content & Privilege Telemetry
- `num_failed_logins`: Count of failed authentication attempts (Brute force indicator).
- `logged_in`: 1 if session successfully authenticated; 0 otherwise.
- `root_shell`: 1 if superuser root shell was spawned; 0 otherwise (Privilege escalation indicator).
- `wrong_fragment`: Count of corrupted IP fragments (Teardrop attack indicator).

---

## 4. Counterfactual Decision Boundary Calculus

A critical contribution of AegisXAI is the **Counterfactual Simulator**. For any alert $x$ with prediction $f(x) \ge 0.5$ (Malicious), the system computes the minimal perturbation vector $\delta$:

$$\min_{\delta} \|\delta\|_2 \quad \text{s.t.} \quad f(x + \delta) < 0.5$$

This identifies the exact operational threshold (e.g. *"If connection rate drops below 85 req/2s, threat probability decreases by 64.3%, classifying the event as Benign"*).

Security teams can immediately utilize this delta to calibrate rate-limiting thresholds and dynamic WAF rules without causing collateral false positives.
