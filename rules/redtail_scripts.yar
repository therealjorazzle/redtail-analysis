rule Redtail_Stager_Script
{
  meta:
    description = "Redtail stager/runner script indicators"
  strings:
    $s1 = "NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec'" ascii
    $s2 = "redtail." ascii
    $s3 = "chmod +x $FILENAME" ascii
    $s4 = "./$FILENAME ssh" ascii
  condition:
    all of them
}

rule Redtail_CronCleaner_Script
{
  meta:
    description = "Redtail cron cleaner / competitor killer"
  strings:
    $c1 = "grep -vE 'wget|curl|/dev/tcp|/tmp|\\.sh|nc|bash -i|sh -i|base64 -d'" ascii
    $c2 = "systemctl disable c3pool_miner" ascii
    $c3 = "rm -rf /tmp /var/tmp /dev/shm" ascii nocase
  condition:
    2 of them
}
