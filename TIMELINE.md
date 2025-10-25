# TIMELINE — Operation Med-Trap

## Week 1 — Deployment & First Contact
- Honeypot online (T-Pot / Cowrie). Inbound attacks begin within minutes.
- Initial uploads captured; repo scaffolded (`artifacts/`, `reports/`, `strings/`).

## Week 2 — Malware & Memory Triage
- UPX-packed binaries unpacked; strings extracted (`strings/` folder).
- IoCs consolidated (`artifacts/iocs_*.txt`, `samples_report.csv`).
- **Reports:** `memory_strings_analysis.md` (narrative), `architecture_comparison.md`.

## Week 3 — CPU & Detection
- **CPU analysis:** threading, affinity, throttling documented in `cpu_optimization_analysis.md`.
- **Detections:** Suricata rules validated; advanced YARA authored and compiled.

## Week 4 — Infrastructure OSINT
- Domains unified and enriched (WHOIS/ASN/rDNS). CSVs produced via `scripts/osint_enrich.sh`.
- Findings summarized in `infrastructure_osint.md`.

## Week 5 — Playbook & Attribution
- **Defensive playbook** published: host, net, and DNS hunts; response checklists.
- **Attribution (anonymized):** assessed as opportunistic cryptomining using European VPS nodes; confidence **medium**.

## Ongoing
- Iterate YARA/Suricata with new IoCs.
- Track infra changes; re-run enrichment periodically.
- Add new reports as new samples or TTPs appear.
