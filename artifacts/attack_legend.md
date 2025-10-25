# Attack Flow Legend (Hybrid Style)
**Style:** Professional MITRE-inspired with a personal flavor  
**Repo:** /home/kali/malware/redtail

---

## Visual vocabulary (what each shape/color means)
Use these classes when creating the Mermaid flowchart so visuals are consistent.

### Shapes
- **Rect (box)** — standard action / step (Execution, Persistence, Impact)  
  Emoji: 🔷
- **Diamond** — decision point (e.g., architecture detection, noexec check)  
  Emoji: 🔶
- **Rounded rect** — subprocess or automation (stager, cleaner)  
  Emoji: ⚙️
- **Cloud** — external network / C2 / pool / Internet resources  
  Emoji: ☁️
- **Cylinder** — data store / persistence (cron, filesystem)  
  Emoji: 🗄️
- **Hex / special** — high-severity impact or operator action (resource hijack)  
  Emoji: 🚨

### Color palette (hex + usage)
- `#1f77b4` — Execution / benign-appearing steps (blue)
- `#ff7f0e` — Decision/Evasion (orange)
- `#2ca02c` — Persistence / OS artefacts (green)
- `#d62728` — Impact / high severity (red)
- `#9467bd` — Network / C2 (purple)
- `#8c564b` — Cleanup/competitor-killer / operator actions (brown)
- `#7f7f7f` — Low-confidence / heuristic info (gray)

### Mermaid class suggestions
(When writing `.mmd`, attach `class <id> <classname>` lines)
- `classDef exec fill:#1f77b4,stroke:#08306b,color:#ffffff,stroke-width:1px;`
- `classDef decision fill:#ff7f0e,stroke:#7f2700,color:#000000,stroke-width:1px,shape:diamond;`
- `classDef persist fill:#2ca02c,stroke:#0b5a0b,color:#ffffff,stroke-width:1px;`
- `classDef impact fill:#d62728,stroke:#7a0a0a,color:#ffffff,stroke-width:1px;`
- `classDef net fill:#9467bd,stroke:#41235b,color:#ffffff,stroke-width:1px;`
- `classDef op fill:#8c564b,stroke:#4a2b24,color:#ffffff,stroke-width:1px;`
- `classDef note fill:#7f7f7f,stroke:#3f3f3f,color:#ffffff,stroke-width:1px,stroke-dasharray: 5 5;`

> Tip: Mermaid doesn't support `shape:diamond` in classDef directly; use `decision` nodes in graph syntax for diamonds and apply class for color/styling.

### Legend entries (text to include in reports/attack_flow.*)
- **Initial Access — 🔷 exec (blue)**  
  Examples: SSH brute force → entry point
- **Execution — 🔷 exec (blue)**  
  Examples: stager script writes `redtail.$ARCH` and executes
- **Persistence — 🗄️ persist (green)**  
  Examples: cron entries, systemd timers, file drops
- **Defense Evasion / Decision — 🔶 decision (orange)**  
  Examples: check `/proc/mounts` for `noexec`, architecture detection
- **Network / C2 — ☁️ net (purple)**  
  Examples: `stratum+ssl://randomx.xmrig.com:443` (pools)
- **Operator actions / Cleaner — ⚙️ op (brown)**  
  Examples: `chattr -ia`, scrub crontabs, kill competing miners
- **Impact — 🚨 impact (red)**  
  Examples: Resource hijacking (XMRig mining), hugepage allocations

### Personality touch (one-liners for diagram captions)
- "Redtail likes all cores, hates competition 🐍💻" — attach near Cleaner node  
- "Pick the fastest path — we check your CPU first ⚡️" — attach near Arch-check decision  
- "If noexec, we hide in /dev/shm 😏" — attach near drop path

---

## How to use (short)
1. When authoring `artifacts/attack_flow.mmd` use the above `classDef` lines at top.  
2. Assign `class <nodeId> <classname>` after node definitions.  
3. Use emojis in node labels for personality, but keep professional wording in the report text.

---

## Files to be produced referencing this legend
- `artifacts/attack_flow.mmd` (Mermaid source)  
- `artifacts/attack_flow.png` (rendered image)  
- `artifacts/attack_legend.md` (this file)

