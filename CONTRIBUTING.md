# CONTRIBUTING

Thanks for your interest in **Operation Med-Trap**. This repo contains live-threat research and malware artifacts. Be careful.

## Ground rules
- **Safety first:** Do not execute samples. Use isolated VMs.
- **No secrets:** Never commit API keys, passwords, or non-redacted IPs/ASNs unless approved.
- **Reproducible:** Include exact commands or scripts for any new analysis.

## Adding analysis
- Place human-readable write-ups under `reports/`.
- Reference inputs/outputs clearly (paths, filenames).
- Keep sections short; prefer links to large logs.

## IoCs & rules
- Add indicators under `artifacts/` (`iocs_*.txt`, CSVs).
- YARA: extend `artifacts/redtail_advanced_rules.yar` or add a new file with a clear name; include `meta` fields.
- Suricata: update `artifacts/redtail_suricata.rules`; comment rationale.

## Scripts
- Put helper scripts under `scripts/`, make them idempotent and commented.
- Avoid external dependencies unless necessary; note requirements at top.

## Git etiquette
- Small, clear commits. Present-tense messages: `docs: add memory strings narrative`.
- Prefer branches per feature: `docs/infrastructure-osint`, `rules/yara-tuning`.

## Review checklist
- [ ] Safety disclaimers present
- [ ] Paths correct and relative to repo root
- [ ] Indicators sourced/cited
- [ ] No sensitive data leaked
