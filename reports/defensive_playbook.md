# Defensive Playbook — Operation Med‑Trap (RedTail)

**Purpose.** A practical SOC runbook to detect, triage, contain, and eradicate RedTail-style cryptominer activity observed in Operation Med‑Trap. It maps detections to MITRE ATT&CK, references our repo artifacts, and provides ready-to-run hunt queries and response checklists.

**Related repo files**
- `artifacts/redtail_advanced_rules.yar` (advanced, cleaned) + `.yarc`
- `artifacts/redtail_suricata.rules` (validated net signatures)
- `reports/memory_strings_analysis.md`, `reports/cpu_optimization_analysis.md`
- `artifacts/iocs_domains.txt`, `iocs_pools.txt`, `iocs_urls.txt`, `samples_report.csv`

---

## 1) Threat summary (TL;DR)
- **What it is:** Miner-oriented payloads using packed ELF, script stagers/cleaners, and stratum pools for monetization.
- **Why it matters:** Sustained CPU drain, cloud spend, service degradation, and attacker footholds that can be repurposed.
- **How it persists:** Script-based startup (cron/systemd), watchdog restarts, cleanup of traces.
- **Key tells:** `stratum`, pool domains, `--threads` / `--max-cpu-usage`, `sched_setaffinity`, hugepages, long-running steady CPU usage.

**Primary ATT&CK mappings**
- Initial Access: T1190 (Exploit Public-Facing App), T1133 (External Remote Services)
- Execution: T1059 (Command Shell), T1204 (User Execution), T1047 (Unix Shell)
- Persistence: T1053.003 (Cron), T1543.002 (Systemd services)
- Defense Evasion: T1027 (Obfuscation/packing), T1070 (Clear Windows/Linux logs/history)
- Discovery/Resource Dev: T1613 (Mining), T1496 (Resource Hijacking)
- C2: T1071 (Application Layer, stratum-like), T1095 (Non-Application Protocol)

---

## 2) Detections

### 2.1 Network (Suricata/IDS)
- **Load rules:** `artifacts/redtail_suricata.rules`
- **Focus:** TLS SNI / cleartext payloads referencing `stratum`, pool hostnames from `iocs_pools.txt`, abnormal persistent outbound TCP to pool ports (3333/4444/5555/7777 variants).

**EVE/ELK examples**
```kql
event.dataset: "suricata.eve" and network.transport: "tcp" and
( url.original: "*stratum*" or http.request.body.content: "*stratum*" or tls.sni: (*yourpools*) )
| stats count, dc(source.ip) by destination.domain, destination.ip, destination.port
| sort by count desc
```

```kql
event.dataset: "suricata.eve" and destination.domain: (
  /* paste top pool domains from artifacts/iocs_pools.txt */
)
| stats count by source.ip, destination.domain, destination.ip, destination.port
```

### 2.2 Host (YARA/EDR)
- **Rules:** `artifacts/redtail_advanced_rules.yar`
- **Scan files/memory:** target suspect folders, tmp paths, and memory snapshots.

**Examples**
```bash
# file scan
yara -r artifacts/redtail_advanced_rules.yar /var/tmp/ /tmp/ /opt/ /usr/local/bin/

# process memory (Linux, with permissions/tooling)
yara -p <pid> artifacts/redtail_advanced_rules.yar
```

**EDR hunts**
- Process command-lines containing: `curl -fsSL|wget -qO-` piped to shell, `chmod +x` in tmp paths, `systemctl enable` with unknown unit files.
- Long-running processes with steady CPU but throttled (10–60%), child of a shell/curl/wget.
- Syscalls/strings: `sched_setaffinity`, `nanosleep`, hugepage requests; files in `/tmp`, `/var/tmp`, `/dev/shm`.

### 2.3 DNS telemetry
- Alert on queries to domains in `artifacts/iocs_domains.txt` and `iocs_pools.txt`.
```kql
dns.question.name: (
  /* paste domains from artifacts/iocs_domains.txt */
)
| stats count by client.ip, dns.question.name, dns.answers.data
```

---

## 3) Hunts (quick wins)

### 3.1 Linux shell telemetry (Elastic)
```kql
process.command_line: (
  "*curl -fsSL*| sh*" or "*wget -qO-*| sh*" or "*chmod +x /tmp/*" or
  "*systemctl enable*" or "*crontab -l*"
)
| stats count by host.hostname, user.name, process.command_line
| sort by count desc
```

### 3.2 CPU behavior outlier (OS Query / EDR)
- Query processes with `pcpu > 10` sustained for >10 minutes excluding known services.
- Cross with processes executed from `/tmp|/var/tmp|/dev/shm`.

### 3.3 File system pivot
```bash
grep -RilE "stratum|--threads|--max-cpu|sched_setaffinity|hugepage" /tmp/ /var/tmp/ /dev/shm/ 2>/dev/null
```

---

## 4) Triage & Analysis

**If a detection fires:**
1. **Snapshot:** `ps auxf`, `ss -tup`, `lsof -p <pid>`, `cat /proc/<pid>/environ`
2. **Preserve artifacts:** copy binaries from tmp dirs, backing up timestamps (`cp --preserve=timestamps`).
3. **YARA confirm:** run YARA against the binary and its memory if possible.
4. **Network verify:** note remote IP/port, SNI, and DNS at time of alert.

**Artifacts to collect**
- Binary + SHA256, strings excerpt, packer status (UPX or not)
- Unit/cron files if present
- Logs: shell history, systemd journal slice near execution time

---

## 5) Response & Eradication

1. **Contain**
   - Kill miner and **parent stager** processes; disable unit/cron entries.
   - Block egress to pool domains/IPs (from `iocs_pools.txt`, `iocs_domains.txt`).

2. **Eradicate**
   - Remove dropped files in `/tmp`, `/var/tmp`, `/dev/shm`, and copied payloads under `/usr/local/bin` or `/opt/`.
   - Remove persistence: unknown units under `/etc/systemd/system/*.service`, crons in `/etc/cron.*` or user crontabs.

3. **Recover**
   - Rotate credentials used by install scripts.
   - Patch exposed service vector; update SSH keys/passwords if abused.
   - Consider reimage for high-confidence compromise.

4. **Improve**
   - Add new IoCs (hashes, domains) to `artifacts/` and SIEM blocklists.
   - Tune Suricata/YARA thresholds if false positives/negatives are found.

---

## 6) Playbook automation stubs

**SIEM saved searches (titles)**
- `REDTAIL: Suricata Stratum Egress`
- `REDTAIL: DNS Queries to Pool Domains`
- `REDTAIL: Linux Shell Stager Behaviors`

**SOAR tasks (pseudo)**
- Enrich domain → WHOIS/ASN → auto-block if matches pool list.
- Host isolate if YARA+Net both confirm.
- Artifact upload to VT/private sandbox → auto-add hash to denylist.

---

## 7) Dashboards (starter widgets)
- **Egress to Pools by Host** (bar): `count(events) by src_ip` filtered on pool domains.
- **Top Processes by CPU (Suspects)** (table): ps/EDR feed excluding allowlist.
- **New Domains Queried (24h)** intersecting with `iocs_domains.txt`.

---

## 8) Appendix — Run snippets

**Get current pools into Suricata variables (manual):**
```bash
# generate a comma list to paste into rules (if needed)
tr -d '\r' < artifacts/iocs_pools.txt | paste -sd, -
```

**Quick host scan**
```bash
yara -r artifacts/redtail_advanced_rules.yar /tmp/ /var/tmp/ /dev/shm/
```

**Hash & strings**
```bash
sha256sum /path/to/suspect
strings -a /path/to/suspect | head -n 200
```

---

## 9) Ownership & SLA
- **Playbook owner:** Joanna / Operation Med‑Trap
- **SLA:** triage within 15m of alert; contain confirmed hosts within 60m; eradicate within same business day; review detections weekly.

