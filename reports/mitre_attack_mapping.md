# MITRE ATT&CK Mapping – Operation Med-Trap (Redtail / XMRig Campaign)

**Scope:** Multi-architecture cryptojacking malware observed in live honeypot telemetry (x86-64, ARMv7, ARM64).  
**Sources:** unpacked binaries, strings analysis, CPU feature inspection, and behavioral heuristics.

---

| Tactic | Technique | ID | Evidence / Observables | Confidence |
|:-------|:-----------|:--|:-----------------------|:------------|
| **Reconnaissance** | Active scanning (Network Service Discovery) | T1046 | Connection attempts across open TCP ports (22, 80, 443, 3306, 5432) captured in Cowrie & Elasticpot logs | High |
| **Resource Development** | Obtain/Develop Cryptomining Infrastructure | T1583.007 | Domains `randomx.xmrig.com`, pool SSL traffic via stratum+ssl | High |
| **Initial Access** | Valid Accounts / Credential Access | T1078 | SSH brute-force attacks with reused credentials in Cowrie logs | High |
| **Execution** | Command-Line Interface | T1059.004 | Shell commands logged in Cowrie session data; observed download/execution of stager scripts | High |
| **Persistence** | Cron Job / Scheduled Task | T1053.003 | Cleaner script creates hidden cron entry to maintain miner process | Medium |
| **Privilege Escalation** | Exploitation for Privilege Escalation | T1068 | Kernel exploit tool references (Linux privilege escalation attempts) | Medium |
| **Defense Evasion** | Obfuscated/Encrypted Files or Information | T1027 | Packed binaries (UPX) and AES routines identified in x86 sample | High |
| **Credential Access** | Credential Dumping via `/etc/shadow` or SSH keys | T1003.008 | File references found in strings (`/etc/passwd`, `/etc/shadow`) | Medium |
| **Discovery** | System Information Discovery | T1082 | CPUID checks, architecture detection (`xgetbv`, `cpuid`, NEON tags) | High |
| **Lateral Movement** | Remote Services (SSH) | T1021.004 | Observed scanning and reuse of compromised SSH credentials | High |
| **Collection** | Data from Local System | T1005 | Miner config stored locally with CPU capability benchmarks | Medium |
| **Command & Control** | Encrypted Channel: TLS/SSL | T1573.002 | Stratum+SSL over port 443 (`randomx.xmrig.com`) | High |
| **Exfiltration** | Exfiltration Over Alternative Protocol | T1048 | Stratum protocol for result submission resembles exfiltration pattern | Medium |
| **Impact** | Resource Hijacking | T1496 | CPU mining (RandomX algorithm) consuming system resources | Very High |

---

**Summary:**  
Redtail demonstrates a multi-architecture design leveraging runtime CPU feature detection and multiple persistence methods.  
The combination of AES-based encryption, NEON/AVX optimizations, and dynamic CPU probing indicates a sophisticated build chain rather than a one-off miner variant.

