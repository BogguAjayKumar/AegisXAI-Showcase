# 🔬 AegisXAI: Threat Scenarios & Incident Walkthroughs

> **Detailed forensic breakdowns of cyber attack scenarios evaluated by AegisXAI.**

---

### Case 1: DoS SYN Flood (Neptune)
- **Target:** Production Web Cluster (`10.0.0.10:80`)
- **Observed Behavior:**
  - Client flooded 485 connection attempts in a 2-second interval.
  - Every connection remained in state `S0` (SYN sent, no final ACK handshake completed).
  - Client returned 0 bytes of application payload.
- **SHAP Breakdown:**
  - `count = 485` ➔ $+0.342$ to Malicious
  - `dst_bytes = 0` ➔ $+0.218$ to Malicious
  - `serror_rate = 1.0` ➔ $+0.185$ to Malicious
- **Analyst Narrative:**
  > *"CRITICAL ALERT: DoS SYN Flood Signature Detected (100.0% Confidence). Target backlog queue is saturated with half-open connections. Mitigate immediately by dropping source IP at perimeter and activating SYN cookies."*
- **Generated Rule:**
  ```snort
  drop tcp 198.51.100.24 any -> 10.0.0.10 80 (msg:"[AegisXAI] Mitigate DoS SYN Flood"; flags:S; threshold:type threshold, track by_src, count 388, seconds 2; sid:3100000; rev:1;)
  ```

---

### Case 2: Data Exfiltration via DNS Tunneling
- **Target:** Internal Active Directory DNS Server (`10.0.0.30:53`)
- **Observed Behavior:**
  - Compromised internal workstation generating 165 UDP DNS queries within 2 seconds.
  - Query payloads abnormally large (`src_bytes = 3840` bytes) encoding base64 chunks in subdomain prefixes (`stolen-data.c2.attacker.com`).
- **SHAP Breakdown:**
  - `service = dns` combined with `src_bytes = 3840` ➔ $+0.285$ to Malicious
  - `count = 165` ➔ $+0.190$ to Malicious
- **Analyst Narrative:**
  > *"HIGH SEVERITY EXFILTRATION: Internal host transmitting high-entropy payload inside DNS query labels. Standard DNS queries rarely exceed 150 bytes. Isolate internal victim host and activate DNS RPZ sinkhole."*

---

### Case 3: Interactive Web Shell / Remote Code Execution (RCE)
- **Target:** DMZ Web Server (`10.0.0.10:443`)
- **Observed Behavior:**
  - Remote attacker issuing interactive HTTP POST commands to an uploaded backdoor.
  - Short request command (`src_bytes = 620`), followed by massive response leak (`dst_bytes = 48200` bytes) dumping `/etc/passwd` and database records.
  - Triggered post-exploitation root execution (`root_shell = 1`).
- **SHAP Breakdown:**
  - `root_shell = 1` ➔ $+0.310$ to Malicious
  - `dst_bytes = 48200` ➔ $+0.245$ to Malicious
  - `duration = 28.5s` ➔ $+0.115$ to Malicious
- **Analyst Narrative:**
  > *"CRITICAL RCE DETECTED: Web application directory compromised with active interactive shell. Server leaking sensitive system data under root privileges."*

---

### Case 4: False Positive Verification (High-Volume API Consumer)
- **Target:** API Gateway (`10.0.0.15:443`)
- **Observed Behavior:**
  - Automated enterprise data analytics pipeline polling API at elevated rate (`count = 120`).
  - Traditional signature or threshold rule would trigger a DoS alert due to high packet count.
  - However: sessions established and terminated cleanly (`flag = SF`), and returned rich payload (`dst_bytes = 18400`).
- **SHAP Breakdown:**
  - `count = 120` ➔ $+0.210$ to Malicious
  - `flag = SF` ➔ $-0.320$ to Benign
  - `dst_bytes = 18400` ➔ $-0.280$ to Benign
  - `same_srv_rate = 0.98` ➔ $-0.150$ to Benign
- **Final Verdict:** **Benign (Risk: 8.5%)**
- **Analyst Outcome:**
  > *"TRIAGE NOTE: False positive averted. Healthy bidirectional throughput and normal session closure prove this is approved enterprise batch traffic. No blocking executed."*
