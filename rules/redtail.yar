rule XMRig_Redtail_Static_UPX_or_Unpacked
{
  meta:
    description = "Detects static XMRig miners as seen in Redtail set"
    author = "Joanna (Week 2)"
  strings:
    $upx1 = "$Info: This file is packed with the UPX executable packer" ascii
    $xm1  = "XMRIG_VERSION" ascii
    $xm2  = "libredtail-http" ascii
    $xm3  = "stratum+ssl://" ascii
    $xm4  = "no valid configuration found, try https://xmrig.com/wizard" ascii
    $don1 = "donate.ssl.xmrig.com" ascii
    $don2 = "donate.v2.xmrig.com" ascii
    $api1 = "api.xmrig.com" ascii
  condition:
    // UPX-packed OR unpacked but miner-like
    $upx1 or (2 of ($xm1,$xm2,$xm3,$xm4,$don1,$don2,$api1))
}
