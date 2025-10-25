# Attribution Assessment — Operation Med‑Trap (RedTail)

**Classification:** Internal // Working Draft  
**Distribution:** Portfolio & Blog-ready (anonymized infrastructure)

---

## Executive Summary
Operation Med‑Trap observed a short, intense burst of activity consistent with an **opportunistic cryptomining campaign** deploying RedTail‑style payloads. The infrastructure appears to be **leased European VPS capacity** routed through a **reseller/hosting chain** with **abuse‑prone reputation**, evidenced by third‑party blocklist status and repeated automated upload attempts (≈16 in ~48 hours). Based on code/behavior overlap (miner flags, stratum markers, CPU optimization strings, script stagers/cleaners) and hosting patterns (low‑cost VPS, small ASN footprint, frequent abuse listings), we assess with **medium confidence** that this activity belongs to a **commodity miner operator** rather than a bespoke APT.

**Bottom line:** This is a revenue‑driven, fast‑moving miner cluster leveraging gray‑market infrastructure, not a targeted espionage effort.

---

## Campaign Overview & Timeline (condensed)
- **Day 0–1:** Honeypot exposure (T‑Pot/Cowrie) begins collecting inbound SSH/Telnet attempts and scripted uploads.  
- **Day 1–2:** Multiple RedTail‑like uploads observed (≈16 attempts over ~48h), indicative of **automated retry logic** rather than manual recon.  
- **Day 2+:** Memory strings and unpacked binaries reveal **miner configuration flags** (`--threads`, `--max-cpu-usage`, `--cpu-priority`), **stratum/pool markers**, and **affinity/throttling** (`sched_setaffinity`, `nanosleep`). Suricata and YARA coverage added.

**Primary objective:** Resource hijacking for cryptomining (ATT&CK **T1496**).

---

## Technical Overlaps (Code, Config, TTPs)
**Binary & Config Signals**
- Packed ELF artifacts (UPX lineage) with post‑unpack miner‑style strings: `stratum`, `pool`, `user`, `pass`, and CPU hints (`avx`, `sse2`, `hugepages`).  
- Threading/affinity primitives (`pthread_create`, `sched_setaffinity`) and duty‑cycle throttling (`nanosleep`, `usleep`).  
- Scripts showing **fetch‑and‑execute** patterns: `curl -fsSL` / `wget -qO-` piped to shell, temp staging under `/tmp|/var/tmp|/dev/shm`, and persistence via **cron/systemd**, with cleanup (`history -c`, `>/dev/null 2>&1`, `rm -f`).

**Infrastructure Signals (anonymized)**
- **European VPS hosting** via a **small reseller chain**, commonly seen in low‑cost VPS markets.  
- Third‑party **DROP‑list status** (spam/abuse reputation), consistent with prior miner/proxy/C2 usage.  
- Short dwell‑time and **repeat upload automation** (≈16 attempts, ~48h) suggest scripted distribution across rotating nodes.

---

## Infrastructure Assessment (Anonymized)
To avoid prematurely exposing specific indicators, we characterize the active nodes as follows:

- **Region:** Europe (Western/Central).  
- **Type:** Data‑center / VPS; not residential or mobile.  
- **Providers:** Small/medium autonomous systems and resellers; frequent presence on community blocklists (e.g., spam/abuse listings).  
- **Routing:** /24‑scale prefixes with occasional upstream transit through regional providers.  
- **Behavior:** Short‑lived nodes used for scripted uploads to exposed services.

> **Analyst note:** When moving this draft to a sharing context, we can append concrete IoCs (IPs/ASNs) from `artifacts/enrichment/domains.enriched.csv` or your source IP logs as an annex, if needed.

---

## Attribution Hypotheses
| Hypothesis | Description | Evidence | Confidence |
|---|---|---|---|
| **H1 — Commodity Miner Operator (most likely)** | Low‑cost VPS nodes, repeat scripted uploads, miner flags/stratum markers, CPU tuning. | Binary strings, stager patterns, DROP‑listed infra, upload cadence (~16/48h). | **Medium** |
| **H2 — Affiliate/Proxy Node** | Third‑party bot or proxy infra relays payloads for various crews. | Abuse‑listed VPS, minimal bespoke TTPs; could be shared. | Low‑Medium |
| **H3 — Targeted Actor (least likely)** | Purpose‑built tooling for a specific victim set. | No bespoke tradecraft; tooling aligns with widely available miner kits. | Low |

**We judge H1 most consistent with observed behaviors and infrastructure.**

---

## Confidence & Gaps
- **Overall confidence:** **Medium.** Strong technical overlap and infra patterning, but absence of unique operator artifacts (e.g., distinctive wallets, bespoke config format) limits high‑confidence attribution.  
- **Key gaps to close:**  
  1) Wallet / user identifiers from pool traffic (if captured).  
  2) Historical passive DNS + cert transparency pivots to map prior clusters.  
  3) Wider sample comparison (hash overlap vs known families).

---

## Detection & Mitigation Implications
- **Network:** Maintain Suricata coverage for stratum markers and blocklist egress to enriched domains/ASNs (see `artifacts/iocs_pools.txt`, `reports/infrastructure_osint.md`).  
- **Host:** Continue YARA sweeps using `artifacts/redtail_advanced_rules.yar`; prioritize hits with CPU tuning + stratum strings.  
- **Ops:** Treat VPS ranges with repeat abuse history as higher‑risk; alert on repeated upload attempts across multiple destinations over short windows.

---

## Sources & Supporting Artifacts (Internal)
- `reports/memory_strings_analysis.md` — memory‑derived IoCs and miner flags.  
- `reports/cpu_optimization_analysis.md` — CPU threading/affinity and throttling.  
- `reports/infrastructure_osint.md` — enrichment playbook and CSV outputs.  
- `artifacts/iocs_*.txt` — pools, domains, URLs.  
- Honeypot ingress logs — show ≈16 upload attempts in ~48h from European VPS nodes.

---

## Analyst Closing Comment
This activity fits the **fast‑turn, revenue‑driven** profile of miner operators leveraging commoditized infrastructure. With medium confidence, we attribute the RedTail‑style attempts against Med‑Trap to **opportunistic cryptomining**, not targeted espionage. We will revisit this assessment if new identifiers (wallets, repeat ASNs, bespoke configs) emerge that tie the cluster to a known crew or affiliate program.
