# Attack Detection Package — Design Spec

## Overview

Pustaka deteksi serangan murni Go, menyediakan antarmuka terpadu + pola registry, mencakup 6 kategori besar dengan 36 detektor. **Implementasi selesai (2026-07-29); paket `session` ditambahkan pada 2026-09-15.**

## Package Structure

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — 注册所有内置 detector
├── injection/               # 注入类攻击 (10)
├── protocol/                # 协议与请求攻击 (9)
├── httpval/                 # HTTP 协议层校验 (7)
├── data/                    # 数据与序列化攻击 (5)
├── file/                    # 文件与敏感数据 (3)
├── session/                 # 会话安全 (2) — 不经过 Engine
│   ├── store.go             # Store interface + MemoryStore
│   ├── tracker.go           # Tracker — 客户端被劫持 / 异地登录
│   ├── lockout.go           # 失败计数、锁定查找与键
│   ├── bruteforce.go        # 渐进退避 / 撞库检测 / GuardLogin
│   └── tamper.go            # Signer — 篡改数据
└── storage/                 # 可插拔存储后端
    ├── storage.go           # Backend interface
    ├── memory.go            # 内存实现 (带 TTL 清理)
    ├── file.go              # JSON 文件持久化
    └── redis/               # Redis 子模块 (可选依赖)
```

## Core API

Antarmuka API lengkap (`Result`, `Detector`, `Engine`, backend penyimpanan `Backend`, validator HTTP) tersedia di dokumen terpisah: **[Dokumentasi API](../api.md)**

- All detectors use pre-compiled regex patterns

## Detectors

| Category | Name | Key Patterns |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS vectors |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, boolean blind, schema enum |
| injection | command | backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass |
| injection | ldap | filter operators `(`, `)`, `&`, `|`, `*` |
| injection | xpath | boolean bypass `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, deep nested query, mutation detect |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO |
| protocol | ssrf | internal IP, 169.254.169.254, IPv6 loopback, gopher/dict |
| protocol | xxe | `<!ENTITY`, parameter entities, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, Set-Cookie/Location injection |
| protocol | host_header | CRLF Host injection, X-Forwarded-Host poisoning |
| protocol | request_smuggling | TE/CL mismatch, dual TE, folded header |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, ACA* header injection |
| protocol | websocket | Upgrade injection, null Origin, ws:// |
| protocol | dns_rebinding | Host header internal IP, localhost, hostname without TLD |
| httpval | method | Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Max size check → 413 (default 10MB) |
| httpval | content_type | MIME whitelist → 415 |
| httpval | csrf_origin | Cross-origin Origin vs Host match |
| httpval | ip_blacklist | Window-based rate limit → auto ban (5/60s → 15min) |
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:数字:`, `C:数字:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |
| session | session_guard | token↔client binding: UA/fingerprint change (client hijack), IP subnet/country change (remote login), login-network history; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
| session | data_tamper | HMAC-SHA256 over canonical params, ±5m timestamp window, nonce replay counter |

## Non-Goals

- No HTTP middleware (pure detection library) — satu-satunya pengecualian adalah `session.Tracker.Guard`, pembungkus tipis yang mengembalikan 401 saat `Check` mendeteksi
- No real-time request interception (caller invokes detection)
- No attack blocking (detection only; ip_blacklist provides block-listing support)

## Status Implementasi (2026-07-29)

- **32 detektor semuanya diimplementasikan** — titik masuk registrasi `all.RegisterAll(engine)`
- **Cakupan pengujian** — 7/8 paket memiliki pengujian (paket `all` menunggu dilengkapi), httpval telah dilengkapi 32 pengujian
- **Code review selesai** — 3 Bug diperbaiki (lihat laporan review), `go vet` nol peringatan
- **Keterbatasan yang diketahui** — submodul `storage/redis/` memerlukan `go mod tidy`; gaya receiver paket protocol menunggu penyatuan
- **Laporan** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

## Addendum — paket session (2026-09-15)

Keamanan sesi ditambahkan sebagai kategori ke-6, dengan batasan desain yang sama seperti di atas:

- **`session.Tracker`** (`session_guard`) — `Issue` mengikat token → subnet IP / UA / sidik jari perangkat; `Check` membandingkan setiap permintaan, memicu `client_hijack` (perubahan UA atau sidik jari, Critical) atau `remote_login` (lintas negara Critical / lintas subnet High); `Guard` langsung mengembalikan 401 saat terdeteksi; `Observe` saat login membandingkan subnet historis pengguna tersebut; `Revoke` langsung membatalkan.
- **`session.Signer`** (`data_tamper`) — Tanda tangan HMAC-SHA256 pada parameter `<timestamp>.<nonce>.<signature>`, urutan verifikasi adalah timestamp → tanda tangan → penghitung nonce, sehingga tanda tangan palsu tidak dapat menghabiskan nonce yang sah. Penghitung replay menggunakan kembali `storage.Backend`.
- **Perlindungan brute force** — `RecordFailure(identity, r)` menghitung kegagalan login dan mengunci pada ambang, berlipat dua tiap kali hingga `MaxLockout` (bawaan 24 jam); `CheckLogin` juga menghitung identitas berbeda per IP klien dan melaporkan `credential_stuffing` pada `StuffingLimit` (bawaan 10); `GuardLogin` adalah middleware endpoint autentikasi, menjawab 429 dengan `Retry-After`. Backoff progresif ada agar mengunci akun sembarang tidak menjadi vektor DoS.
- **Penyimpanan** — Struktur sesi tidak dapat diekspresikan dengan `storage.Backend` yang hanya mendukung penghitung/blokir, sehingga ditambahkan `session.Store` (`Save` / `Load` / `Delete`) + `MemoryStore`; `storage.Backend` dan ketiga implementasinya tidak diubah.
- **Tidak didaftarkan ke `Engine`** — `Detector.Detect(input string)` tidak dapat mengakses token / IP klien / UA, sehingga `Tracker` menerima `*http.Request` secara langsung; `all.RegisterAll` tetap hanya mendaftarkan detektor tanpa konfigurasi.
- **Pengujian** — Paket `session` memiliki 5 file pengujian (store / tracker / tamper / lockout / bruteforce), `go test ./... -race` lulus.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
