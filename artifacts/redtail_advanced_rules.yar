/* 
  RedTail Advanced YARA Rules
  ---------------------------
  Three enhanced rules tuned for Operation Med- Trap evidence:
    1) Memory/CPU: stratum/pool + CPU tuning hints (in memory or on disk)
    2) Behavioral (packed miner): UPX + miner behaviors (threads/affinity/hugepages)
    3) Script stager/cleaner: curl|wget -> chmod +x, cron/systemd persistence, log cleaners

  Notes:
  - These rules are Linux-centric (ELF), but the script rule is file-agnostic (text).
  - Tighten by adding your specific pool domains from artifacts/iocs_pools.txt under the $pool_* group.
  - Safe defaults: no hardcoded wallets; conditions require multiple indicators to reduce FPs.

  Usage examples:
    yara -r redtail_advanced_rules.yar ~/malware/redtail/samples/
    yarac redtail_advanced_rules.yar out.yarc && yara -r out.yarc /path

  Author: Joanna (Operation Med- Trap) — assist
  License: CC-BY 4.0
*/

import "elf"
import "math"

rule redtail_mem_stratum_cpu
{
  meta:
    author = "joanna"
    description = "RedTail memory-oriented miner indicators: stratum/pool + CPU throttling/tuning flags"
    reference = "Operation Med- Trap / Task 8"
    confidence = "high"
    version = "1.0"

  strings:
    // Miner / protocol markers
    $proto_stratum   = "stratum" nocase ascii
    $proto_pool      = "pool" nocase ascii
    $proto_user      = "user" nocase ascii
    $proto_pass      = "pass" nocase ascii

    // CPU / tuning hints
    $cpu_threads1    = "--threads" ascii
    $cpu_threads2    = "-t " ascii
    $cpu_prio        = "--cpu-priority" ascii
    $cpu_usage       = "--max-cpu-usage" ascii
    $cpu_avx         = "avx" nocase ascii
    $cpu_sse         = "sse2" nocase ascii
    $cpu_aesni       = "aesni" nocase ascii
    $cpu_huge1       = "hugepage" nocase ascii
    $cpu_huge2       = "huge-pages" nocase ascii

    // Threading / affinity / throttling
    $thr_pthread     = "pthread_create" ascii
    $thr_affinity    = "sched_setaffinity" ascii
    $thr_sleep1      = "nanosleep" ascii
    $thr_sleep2      = "usleep" ascii
    $thr_sleep3      = "clock_nanosleep" ascii

  condition:
    (uint32(0) == 0x7F454C46 or true)
    and any of ($proto_stratum, $proto_pool, $proto_user, $proto_pass)
    and ( $cpu_threads1 or $cpu_threads2 or $cpu_prio or $cpu_usage or $cpu_avx or $cpu_sse or $cpu_aesni or $cpu_huge1 or $cpu_huge2 )
    and ( $thr_affinity or $thr_pthread or $thr_sleep1 or $thr_sleep2 or $thr_sleep3 )
}

rule redtail_behavior_packed_miner
{
  meta:
    author = "joanna"
    description = "RedTail miner behavioral signature: UPX/packed ELF + miner runtime hints (threads/affinity/hugepages)"
    reference = "Operation Med- Trap / Task 8"
    confidence = "medium-high"
    version = "1.0"

  strings:
    // UPX/packer artifacts
    $upx_magic  = "UPX!" ascii
    $upx0       = "UPX0" ascii
    $upx1       = "UPX1" ascii
    $sec_upx    = ".upx" ascii
    $sec_packed = ".ptext" ascii

    // Miner style flags / hints
    $m_threads  = "--threads" ascii
    $m_usage    = "--max-cpu-usage" ascii
    $m_priority = "--cpu-priority" ascii
    $m_huge     = "hugepage" nocase ascii
    $m_aff      = "sched_setaffinity" ascii
    $m_sleep    = "nanosleep" ascii
    $m_stratum  = "stratum" nocase ascii
    $m_pool     = "pool" nocase ascii

  condition:
    uint32(0) == 0x7F454C46 and elf.number_of_sections > 0 and
    ( $upx_magic or $upx0 or $upx1 or $sec_upx or $sec_packed )
    and
    ( ( $m_threads or $m_usage or $m_priority or $m_huge or $m_aff or $m_sleep ) and ( $m_stratum or $m_pool ) )
}

rule redtail_script_stager_cleaner
{
  meta:
    author = "joanna"
    description = "RedTail stager/cleaner script traits: curl|wget fetch, chmod +x, tmp paths, cron/systemd persistence, log cleanup"
    reference = "Operation Med- Trap / Task 8"
    confidence = "high"
    version = "1.0"

  strings:
    // Fetch & execute
    $sh_curl1   = "curl -fsSL" nocase ascii
    $sh_curl2   = "curl -s" nocase ascii
    $sh_wget1   = "wget -qO-" nocase ascii
    $sh_wget2   = "wget http" nocase ascii
    $sh_chmod   = "chmod +x" ascii
    $sh_pipe    = "| sh" ascii
    $sh_exec    = "sh -c" ascii

    // Staging directories
    $tmp1       = "/tmp/" ascii
    $tmp2       = "/var/tmp/" ascii
    $tmp3       = "/dev/shm/" ascii

    // Persistence (cron/systemd)
    $cron1      = "crontab -l" ascii
    $cron2      = "/etc/cron." ascii
    $cron3      = "echo \"* * * * *" ascii
    $systemd1   = "systemctl enable" ascii
    $systemd2   = "[Service]" ascii
    $systemd3   = "/etc/systemd/system/" ascii

    // Cleanup / stealth
    $clean1     = "history -c" ascii
    $clean2     = ">/dev/null 2>&1" ascii
    $clean3     = "rm -f" ascii
    $clean4     = "killall" ascii

  condition:
    ( any of ( $sh_curl1, $sh_curl2, $sh_wget1, $sh_wget2 ) and ( $sh_pipe or $sh_chmod or $sh_exec ) )
    and ( $tmp1 or $tmp2 or $tmp3 )
    and ( any of ( $cron1, $cron2, $cron3, $systemd1, $systemd2, $systemd3 ) or any of ( $clean1, $clean2, $clean3, $clean4 ) )
}
