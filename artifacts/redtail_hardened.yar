rule XMRig_Redtail_Static_UPX_or_Unpacked_v2
{
  meta:
    description = "XMRig-like miner (Redtail set), static ELF"
    author = "Joanna (Week 2)"
  strings:
    $upx1 = "$Info: This file is packed with the UPX executable packer" ascii nocase
    $xm1  = "XMRIG_VERSION" ascii nocase
    $xm2  = "libredtail-http" ascii nocase
    $xm3  = "stratum+ssl://" ascii nocase
    $xm4  = "no valid configuration found, try https://xmrig.com/wizard" ascii nocase
    $don1 = "donate.ssl.xmrig.com" ascii nocase
    $don2 = "donate.v2.xmrig.com" ascii nocase
    $api1 = "api.xmrig.com" ascii nocase
  condition:
    (filesize < 30MB) and
    ( $upx1 or (2 of ($xm1,$xm2,$xm3,$xm4,$don1,$don2,$api1)) )
}
