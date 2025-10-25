# Operation Med-Trap
Author: **Jo Razzle**  
Status: Active research repository

## Purpose
Operation Med-Trap is a live threat-intel and malware-analysis project built around a healthcare-themed honeypot. The repo documents real attacker behavior (scripts, binaries, infrastructure) and turns it into actionable detections (YARA, Suricata) and SOC playbooks.

## What’s here
```
.
├─ artifacts/                # IoCs, rules, graphs, CSVs
│  ├─ iocs_domains.txt
│  ├─ iocs_pools.txt
│  ├─ iocs_urls.txt
│  ├─ redtail_advanced_rules.yar(.yarc)
│  ├─ redtail_suricata.rules
│  └─ graph_pools.png, samples_report.csv, *.yar
├─ reports/                  # Analyst write-ups
│  ├─ cpu_optimization_analysis.md
│  ├─ memory_strings_analysis.md
│  ├─ infrastructure_osint.md
│  ├─ defensive_playbook.md
│  └─ attribution_assessment.md
├─ strings/                  # Per-sample strings outputs
├─ samples/                  # Captured binaries (do not execute)
├─ scripts/                  # Helper scripts (e.g., osint_enrich.sh)
└─ README.md / CONTRIBUTING.md / TIMELINE.md
```

## Quick start (safety-first)
> Never execute samples. Work on an isolated VM. Treat everything in `samples/` as hostile.

### YARA
```bash
# from repo root
yara -r artifacts/redtail_advanced_rules.yar samples/ | sed -n '1,50p'
# optional compile
yarac artifacts/redtail_advanced_rules.yar artifacts/redtail_advanced_rules.yarc
yara -r artifacts/redtail_advanced_rules.yarc samples/ | sed -n '1,50p'
```

### Suricata (network)
Add `artifacts/redtail_suricata.rules` to your Suricata include path and reload. Prioritize alerts on domains in `artifacts/iocs_pools.txt` / `iocs_domains.txt`.

### OSINT enrichment
```bash
# builds unified domain list + CSV enrich
bash scripts/osint_enrich.sh
```

## Reports index
- CPU: `reports/cpu_optimization_analysis.md`
- Memory: `reports/memory_strings_analysis.md`
- OSINT: `reports/infrastructure_osint.md`
- Playbook: `reports/defensive_playbook.md`
- Attribution: `reports/attribution_assessment.md`

## Data handling
- Redact sensitive IPs/ASNs in public artifacts unless approved.
- Prefer hashes/domains over full URLs.
- Do not commit secrets.

## License
Code/rules: MIT. Docs: CC-BY 4.0.
Attribution appreciated: “Jo Razzle — Operation Med-Trap”.
