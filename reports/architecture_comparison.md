# Architecture Comparison — Redtail / XMRig (Operation Med-Trap)

**Generated:** $(date -Iseconds)
**Repo:** $PWD

| File | Detected Type | Size (bytes) | Strings Count | High-value IOC Count | Build Indicators |
|---|---|---:|---:|---:|---|
| 89782d8142297907c9962eebdae29c28df86805a99f38a683ab55c8fa1596dd8 | ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped | 4269592 | 142 | 23 | randomx;UV_THREADPOOL_SIZE |
| 229496b55d0668a40fe3d969ba4e942dc2c2fd7452b3d6f79c6beb0db631dc12 | ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, stripped | 3862820 | 140 | 23 | randomx;UV_THREADPOOL_SIZE |
| d6e0eb28cfe1b224f061eff0581091dac985516c78d222f4921587d2ec612010 | ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped | 5073160 | 55917 | 187 | AES;AES;AES;randomx;randomx;randomx;randomx;randomx;randomx;randomx;randomx;randomx;aes;aes;RandomX;RandomX;RandomX;aes;aes;AES;AES;aes;aes;AES;aes;AES;aes;aes;aes;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;aes;aes;AES;aes;AES;aes;AES;aes;aes;AES;aes;AES;aes;AES;aes;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;AES;aes;UV_THREADPOOL_SIZE;CPUID;cpuid;randomx;AES;RandomX;RandomX;RandomX;RandomX;RandomX;RandomX;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;AES;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;cpuid;Aes;AES;AES;AES;AES |
| ee7a31fb0d3c29ca435f08fd147a434c6db921b69d32c8894539a8199b0b15c0 | ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), statically linked, stripped | 5250248 | 142 | 23 | UV_THREADPOOL_SIZE;randomx |

---

## Analyst Summary & Conclusions

Conclusion: Multi-architecture XMRig/Redtail variants share high-value IOCs (randomx, api.xmrig.com), CPU feature probes (cpuid/xgetbv on x86; NEON on ARM), and static-linked/stripped builds — consistent with a single build pipeline. Confidence: HIGH.

