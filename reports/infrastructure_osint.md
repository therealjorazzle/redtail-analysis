# Infrastructure OSINT — RedTail

**Scope.** Enrich RedTail pool/domains and URLs with DNS, WHOIS/RDAP, ASN, geolocation, and hosting patterns. This playbook is reproducible on Kali and produces CSV artifacts you can commit to the repo.

**Inputs**
- `artifacts/iocs_pools.txt`
- `artifacts/iocs_domains.txt`
- `artifacts/iocs_urls.txt` (parsed for domains)

**Outputs (recommended)**
- `artifacts/enrichment/pool_domains_enriched.csv`
- `artifacts/enrichment/all_domains_enriched.csv`
- `artifacts/enrichment/findings.md` (TL;DR observations)
- Optional graphs: `artifacts/enrichment/graphs/*.png`

---

## TL;DR (fill after running)
- **Registrar/host overlap:** _e.g., many domains at {Registrar} and resolving to {Provider/ASN}._
- **Geoclusters:** _e.g., majority in {country}/{region}; time-windowed DNS shifts on {dates}._
- **Fast-flux / rotation:** _e.g., >N unique A records per domain over 24h._
- **Shared infra fingerprints:** _common rDNS patterns, name servers, TLS CN/SAN reuse._
- **Actionables:** _blocklist ASNs {…}; alert on new resolutions to those ASNs; watch NS {…}_

> Update this section after the scripts/cmds below generate the CSVs.

---

## 1) Quick one-liners (sanity checks)

From repo root `~/malware/redtail`:

```bash
# unique domains from artifacts (pools + domains + urls)
( cat artifacts/iocs_pools.txt artifacts/iocs_domains.txt 2>/dev/null || true;   sed -nE 's#https?://([^/]+)/?.*#\1#p' artifacts/iocs_urls.txt 2>/dev/null || true ) | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//' | sort -u > artifacts/enrichment/domains.all.txt

# current A/AAAA (fast)
mkdir -p artifacts/enrichment
while read d; do
  printf "%s," "$d"
  dig +short A "$d" | tr '\n' ' ' | sed 's/ $//' | awk '{printf "%s,", $0}'
  dig +short AAAA "$d" | tr '\n' ' ' | sed 's/ $//' | awk '{printf "%s,", $0}'
  dig +short CNAME "$d" | tr '\n' ' ' | sed 's/ $//' | awk '{printf "%s", $0}'
  printf "\n"
done < artifacts/enrichment/domains.all.txt > artifacts/enrichment/domains.now.dns.csv
echo "Wrote artifacts/enrichment/domains.now.dns.csv"
```

CSV columns: `domain, A_list, AAAA_list, CNAME_list`

---

## 2) Deeper enrichment (WHOIS/RDAP, ASN, rDNS, NS/MX)

### 2.1 Helper script — `osint_enrich.sh`
Creates a compact CSV with registrar, dates, ASN, org, and geoinfo. Uses public WHOIS and Team Cymru for ASN.

```bash
cat > scripts/osint_enrich.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

IN="artifacts/enrichment/domains.all.txt"
OUT="artifacts/enrichment/domains.enriched.csv"
TMP="artifacts/enrichment/tmp"
mkdir -p "$(dirname "$OUT")" "$TMP"

echo "domain,A,AAAA,CNAME,NS,MX,ASN,ASN_Org,IP_Countries,Registrar,Created,Updated,rDNS" > "$OUT"

while read -r d; do
  [ -z "$d" ] && continue

  A=$(dig +short A "$d" | tr '\n' ' ' | sed 's/ $//')
  AAAA=$(dig +short AAAA "$d" | tr '\n' ' ' | sed 's/ $//')
  CNAME=$(dig +short CNAME "$d" | tr '\n' ' ' | sed 's/ $//')
  NS=$(dig +short NS "$d" | tr '\n' ' ' | sed 's/ $//')
  MX=$(dig +short MX "$d" | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')

  # rDNS for first A (if any)
  RDNS=""
  FIRSTIP=$(echo "$A" | awk '{print $1}')
  if [[ -n "$FIRSTIP" ]]; then
    RDNS=$(dig +short -x "$FIRSTIP" | tr '\n' ' ' | sed 's/ $//')
  fi

  # ASN via Team Cymru (one IP is enough to classify infra owner; join all if needed)
  ASN=""; ASNORG=""; COUNTRIES=""
  if [[ -n "$A" ]]; then
    # query each IPv4 in A-list
    for ip in $A; do
      CY=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | awk 'NR>1{print $1"|"$3"|"$7}')
      # CY format: ASN|ASName|Country
      if [[ -n "$CY" ]]; then
        IFS='|' read -r asn asname ctry <<<"$CY"
        ASN="${ASN} ${asn}"
        ASNORG="${ASNORG} ${asname}"
        COUNTRIES="${COUNTRIES} ${ctry}"
      fi
    done
    ASN=$(echo "$ASN" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')
    ASNORG=$(echo "$ASNORG" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')
    COUNTRIES=$(echo "$COUNTRIES" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')
  fi

  # WHOIS (registrar + dates) — heuristic parsing, varies by TLD
  W=$(whois "$d" 2>/dev/null || true)
  REG=$(echo "$W" | sed -nE 's/Registrar:[ ]*(.*)/\1/p; s/registrar:[ ]*(.*)/\1/p' | head -1 | tr -d '\r')
  CR=$(echo "$W" | sed -nE 's/Creation Date:[ ]*(.*)/\1/p; s/created:[ ]*(.*)/\1/p' | head -1 | tr -d '\r')
  UP=$(echo "$W" | sed -nE 's/Updated Date:[ ]*(.*)/\1/p; s/updated:[ ]*(.*)/\1/p' | head -1 | tr -d '\r')

  echo "$d,"$A","$AAAA","$CNAME","$NS","$MX","$ASN","$ASNORG","$COUNTRIES","$REG","$CR","$UP","$RDNS"" >> "$OUT"
done < "$IN"

echo "Wrote $OUT"
SH

chmod +x scripts/osint_enrich.sh
```

Run it:
```bash
mkdir -p scripts artifacts/enrichment
# ensure domain list exists (from step 1)
[ -f artifacts/enrichment/domains.all.txt ] || echo "No domains file; run step 1."

# dependencies (if needed)
sudo apt-get update && sudo apt-get install -y whois dnsutils

# enrich
scripts/osint_enrich.sh
```

This produces:
- `artifacts/enrichment/domains.enriched.csv` (primary dataset)

---

## 3) (Optional) Historical & certificate pivots

These need Internet access and may have rate limits.

- **Passive DNS / history:** `securitytrails`, `dnsdb`, `virustotal`, `riskIQ` (if you have API keys).
- **crt.sh (cert transparency):**
```bash
# simple scrape (lightweight)
d=example.com
curl -s "https://crt.sh/?q=%25.$d&output=json" | jq -r '.[].name_value' | sort -u
```
- **RDAP (structured whois):**
```bash
# will 302 to the correct RDAP server
curl -sL "https://rdap.org/domain/example.com" | jq
```

> If you have tokens for any of the above, we can wire quick Python scripts to bulk-enrich and append columns.

---

## 4) Turning data into findings (template)

Create `artifacts/enrichment/findings.md` and summarize:

### 4.1 Hosting & ASN Patterns
- Reused ASNs: list top ASNs by domain count.
- Note if pools resolve to CDN edges vs bare metal hosts.

### 4.2 Registrar / NS Overlap
- Top registrars and name servers.
- Any parked or privacy-masked domains?

### 4.3 Geography
- Countries by IP count; odd/geopolitically relevant clusters.

### 4.4 Temporal Behavior
- Track resolutions across two days (re-run step 2 tomorrow and diff). Note fast-flux.

### 4.5 Pivotable Artifacts
- rDNS stems, certificate CN/SAN fragments, uncommon NS providers.

### 4.6 Detections/Blocks (Actionable)
- Block outbound to ASNs {…}; alert on new pool domains resolving to those ASNs.
- Monitor queries to the set of NS {…}.

---

## 5) ELK / Splunk Hunt Starters

**DNS egress (ELK)**
```kql
dns.question.name : (*yourdomain1.tld* or *yourdomain2.tld*)
```

**Suricata EVE (Stratum proto via HTTP/TCP)**
```kql
event.dataset : suricata.eve and network.protocol:tcp and
(
  url.original : "*stratum*" or
  http.request.body.content : "*mining*" or
  tls.sni : (*yourpools*)
)
```

**Splunk (DNS)**
```
index=dns  query IN ("domain1.tld","domain2.tld","domain3.tld")
| stats count by src_ip, query, answer
```

Replace placeholders with real values from `domains.enriched.csv` once generated.

---

## 6) Commit workflow (suggested)

```bash
cd ~/malware/redtail
git checkout -b docs/infrastructure-osint

# ensure outputs exist
ls artifacts/enrichment/domains.all.txt artifacts/enrichment/domains.enriched.csv

git add artifacts/enrichment/domains.now.dns.csv        artifacts/enrichment/domains.all.txt        artifacts/enrichment/domains.enriched.csv        scripts/osint_enrich.sh        reports/infrastructure_osint.md

git commit -m "docs: infra OSINT enrichment playbook + scripts and CSV outputs"
git push -u origin HEAD
```

---

## Appendix — Troubleshooting

- **Empty WHOIS fields**: some TLDs use RDAP only or rate-limit aggressively; retry or use `rdap.org` JSON.
- **ASN empty**: only IPv6 results or no A records; add IPv6 ASN lookup (Team Cymru has a v6 endpoint; or use `bgpview.io` API).
- **Fast-flux**: schedule the script hourly and diff `A` lists; if you want, we can add a cron snippet.
