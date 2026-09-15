# Security Go — pustaka deteksi serangan

[简体中文](../../../README.md) · [English](../../../README-EN.md)

Pustaka deteksi serangan yang ditulis dalam bahasa Go, mencakup **36 detektor**, **6 kategori serangan utama**, dan **3 backend penyimpanan yang dapat dipasang**. Antarmuka terpadu + pola registry, murni pustaka deteksi, cocok untuk kerangka HTTP Go mana pun.

## Konsep Desain

### Prinsip Inti

- **Deteksi tanpa dependensi** — semua detektor hanya menggunakan `regexp` dari pustaka standar Go, tanpa dependensi eksternal
- **Antarmuka terpadu** — setiap detektor mengimplementasikan antarmuka `Detector` (`Name()` + `Detect()`), dikelola secara terpadu melalui registry `Engine`
- **Regex pra-kompilasi** — semua pola dikompilasi saat inisialisasi `var`, tanpa overhead saat runtime
- **Konfigurasi sesuai kebutuhan** — detektor injeksi/protokol/data/file bersifat plug-and-play; validator HTTP dan deteksi keamanan sesi memerlukan konfigurasi kustom aplikasi

### Arsitektur Desain

```
                         ┌───────────────────────────────┐
                         │        security.Engine         │
                         │  ┌─────────────────────────┐  │
                         │  │    Detector Registry     │  │
                         │  │   map[string]Detector    │  │
                         │  └─────────────────────────┘  │
                         │                               │
                         │  Detect(name, input)          │
                         │  DetectAll(input)             │
                         │  DetectRequest(*http.Request) │
                         └──────────────┬────────────────┘
                                        │
          ┌─────────────────┬───────────┴───────────┬─────────────────┐
          │                 │                       │                 │
   ┌──────▼──────┐   ┌──────▼──────┐   ┌────────────▼────────┐   ┌───▼───────────┐
   │  injection  │   │  protocol   │   │        data         │   │     file      │
   │   (10 个)   │   │   (9 个)    │   │       (5 个)        │   │    (3 个)     │
   │             │   │             │   │                     │   │               │
   │  xss, sql,  │   │  ssrf, xxe, │   │  deser, csv,        │   │  traversal,   │
   │  command,   │   │  header,    │   │  mail, jwt,         │   │  upload,      │
   │  nosql,     │   │  host,      │   │  proto_poll         │   │  data_leak    │
   │  ldap,      │   │  smuggling, │   │                     │   │               │
   │  xpath,     │   │  redirect,  │   │                     │   │               │
   │  jndi, ssi, │   │  cors, ws,  │   │                     │   │               │
   │  graphql,   │   │  dns_rebind │   │                     │   │               │
   │  ssti       │   │             │   │                     │   │               │
   └─────────────┘   └─────────────┘   └─────────────────────┘   └───────────────┘
                                                                          │
          ┌───────────────────────────────────────────────────────────────┤
          │                                                               │
   ┌──────▼──────────┐                                         ┌──────────▼──────────┐
   │     httpval     │                                         │       storage       │
   │     (7 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  cookie,nested  │                                         │                    │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘

   ┌─────────────────────────────────────────────────────────────────────┐
   │  session (2)   outside the Engine registry                          │
   │                                                                     │
   │  Tracker (session_guard)  +  Signer (data_tamper)                   │
   │  Issue / Check / Observe / Guard / Revoke    Sign / Verify          │
   └─────────────────────────────────────────────────────────────────────┘
```

> Paket `session` tidak didaftarkan melalui `Engine`: validasi sesi harus membaca `*http.Request` secara lengkap (token, IP klien, User-Agent),
> dan memerlukan penyimpanan serta kunci dari aplikasi, sehingga dipanggil langsung sebagai middleware, lihat bagian "Konfigurasi Keamanan Sesi" di bawah.

### Alur Data

```
HTTP Request
     │
     ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│ collectInputs│────▶│  DetectAll()    │────▶│  []*Result   │
│ URL, Query,  │     │  逐个检测器调用   │     │  聚合结果     │
│ Headers,     │     │  Detect(input)  │     │              │
│ Cookies      │     └─────────────────┘     └──────────────┘
└──────────────┘
```

### Tingkat Keparahan

| Tingkat | Keterangan | Skenario Umum |
|------|------|---------|
| `SeverityLow` | Risiko rendah | Metode HTTP tidak sah, Content-Type tidak cocok |
| `SeverityMedium` | Risiko sedang | Sinyal lemah: salah konfigurasi CORS, open redirect, introspeksi GraphQL, ditambah pola tanpa konteks yang sengaja dipisahkan tiap detektor (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, backtick, `{#…#}`, `__proto__:`, nama magic method PHP) — lazim di tutorial dan konten biasa |
| `SeverityHigh` | Risiko tinggi | Sinyal kuat: XSS, injeksi SQL, SSRF, path traversal, anomali sesi |
| `SeverityCritical` | Kritis | Sinyal kuat: injeksi perintah, JNDI, SSTI, XXE, kebocoran data, deserialisasi (objek terserialisasi PHP / pickle / Java / .NET) |

## Fitur yang Diimplementasikan

### Serangan Injeksi (10)

| Detektor | Pola Deteksi |
|--------|---------|
| **XSS** | `<script>`, event handler `on[a-z]+=`, protokol palsu `javascript:`, injeksi SVG/CSS, `eval()`, `document.cookie` |
| **Injeksi SQL** | `UNION SELECT` (termasuk bypass `/**/`), `sleep/benchmark/pg_sleep`, blind boolean, enumerasi `information_schema`, `xp_cmdshell` |
| **Injeksi Perintah** | backtick, `$()`, karakter pipe, `/dev/tcp`, `system/exec/shell_exec` PHP, eksekusi berantai `&&` `;` `\|\|` |
| **Injeksi NoSQL** | Operator MongoDB `$ne` `$gt` `$regex` `$where`, `$func`, injeksi kunci JSON |
| **Injeksi LDAP** | Operator filter `(\|(&(!`, `objectClass=*`, bypass encoding URL |
| **Injeksi XPATH** | Bypass boolean `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, obfuskasi `${lower:j}`, variabel lingkungan `${env:}`, protokol `ldap/rmi/dns` |
| **Injeksi SSI** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **Injeksi GraphQL** | Introspeksi `__schema`/`__type`, DoS nested dalam (5+ lapis), deteksi `mutation` |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, traversi MRO Python, akses `config/self` |

### Serangan Protokol & Permintaan (9)

| Detektor | Pola Deteksi |
|--------|---------|
| **SSRF** | IP internal (127/10/172.16/192.168), `169.254.169.254`, IPv6 loopback, protokol `gopher/dict/file/ftp` |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, entitas parameter `%entity;`, deklarasi DOCTYPE |
| **Injeksi Header HTTP** | CRLF `%0d%0a` / `\r\n`, injeksi Set-Cookie/Location/Content-Length |
| **Serangan Host Header** | Injeksi Host CRLF, poisoning `X-Forwarded-Host`, `X-Original-URL` |
| **Request Smuggling** | Ketidakcocokan Transfer-Encoding/Content-Length, header TE ganda, kebingungan header terlipat `\x0b` |
| **Open Redirect** | URL relatif protokol `//evil.com`, protokol palsu `javascript:/data:` |
| **Bypass CORS** | `Origin: null`, injeksi header `Access-Control-Allow-*` |
| **Pembajakan WebSocket** | Injeksi header Upgrade, bypass Origin null, URL `ws://` |
| **DNS Rebinding** | IP internal pada Host header, localhost, nama host pendek tanpa TLD |

### Validasi Lapisan Protokol HTTP (7)
| **Kedalaman Penyarangan JSON** | Memindai secara streaming dengan `json.Decoder`: menandai bom JSON saat kedalaman atau jumlah elemen melewati batas (kedalaman bawaan 32). JSON tidak valid atau terpotong tidak pernah memicu |
| **Atribut Set-Cookie** | Menandai `Set-Cookie` tanpa `Secure`/`HttpOnly`/`SameSite`, nilai terlalu panjang, atau nilai kosong; atribut yang hilang digabung dalam satu hasil |

| Detektor | Keterangan |
|--------|------|
| **Metode HTTP** | Hanya mengizinkan GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH, lainnya mengembalikan peringatan |
| **Ukuran Body Permintaan** | Melebihi batas (default 10MB) memicu peringatan |
| **Content-Type** | Hanya mengizinkan daftar putih tipe MIME yang dikonfigurasi |
| **CSRF Origin** | Mendeteksi apakah Origin permintaan lintas domain cocok dengan Host, mendukung daftar putih tambahan |
| **IP Blacklist** | Blokir otomatis setelah N kali serangan dalam jendela waktu (default 5x/60s → blokir 15 menit), mendukung penyimpanan File/Redis/Memory |

### Serangan Data & Serialisasi (5)

| Detektor | Pola Deteksi |
|--------|---------|
| **Deserialisasi** | Objek serialisasi `O:angka:` / `C:angka:`, `unserialize()`, metode ajaib (`__wakeup`/`__destruct`); mencakup muatan PHP / pickle / Java / .NET |
| **Injeksi CSV** | `=cmd\|`, `@SUM(`, prefiks rumus `+`/`-`, `HYPERLINK`/`DDE` |
| **Injeksi Header Email** | Injeksi Bcc/Cc/From/To, MIME multipart, parameter boundary |
| **Serangan JWT** | Bypass `alg: none`, path traversal `kid`, deteksi tanda tangan kosong (analisis decoding struktur) |
| **Polusi Prototipe** | Kunci `__proto__`/`constructor`, `__defineGetter__`/`__defineSetter__` |

### File & Data Sensitif (3)

| Detektor | Pola Deteksi |
|--------|---------|
| **Path Traversal** | `../`, `..\\`, `php://filter`/`php://input`, null byte, bypass encoding URL, `/etc/passwd` |
| **Upload Berbahaya** | Daftar putih ekstensi (15 jenis) + pemindaian konten tag PHP `<?php`/`<?=` |
| **Kebocoran Data** | Nomor kartu kredit, AWS Access Key, kunci privat `-----BEGIN`, string koneksi database, API Token, JWT Secret, GitHub PAT |

### Keamanan Sesi (2)

| Detektor | Pola Deteksi |
|--------|---------|
| **Penjaga Sesi** (`session_guard`) | token diikat ke klien saat sesi dibuat, dibandingkan pada setiap permintaan: perubahan User-Agent atau sidik jari perangkat dianggap **klien dibajak** (Critical); IP klien jatuh ke subnet atau negara lain dianggap **login dari lokasi lain** (High/Critical); `Observe()` saat login membandingkan subnet historis, munculnya subnet baru langsung memicu peringatan. Sesi diperpanjang secara sliding, `Revoke()` dapat langsung membatalkan; `RecordFailure()` menghitung percobaan gagal dan mengunci token begitu ambang tercapai dalam jendela waktu, `Check()` lalu melaporkan `token_locked`, dan `ClearFailures()` mereset hitungan saat login berhasil; `CheckLogin()` juga menangkap credential stuffing (satu klien gagal terhadap terlalu banyak identitas berbeda → `credential_stuffing`), dan kunci berlipat dua tiap pengulangan, dibatasi 24 jam |
| **Manipulasi Data** (`data_tamper`) | Parameter permintaan ditandatangani dengan HMAC-SHA256 (`timestamp.nonce.signature`), mengidentifikasi perubahan parameter, ketidakcocokan kunci, selisih timestamp, dan pemutaran ulang tanda tangan (penghitung nonce) |

### Backend Penyimpanan (3)

| Backend | Keterangan |
|------|------|
| **Memory** | `sync.Mutex` + map, pembersihan otomatis entri kedaluwarsa setiap 30 detik |
| **File** | Persistensi file JSON, flush saat Close |
| **Redis** | Submodul terpisah, Pipeline Incr + TTL, memerlukan `go-redis/v9` |

## Petunjuk Penggunaan

### Instalasi

```bash
go get github.com/erikwang2013/security-go
```

### Memulai dengan Cepat

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // 一键注册 27 个零配置检测器

    // 单个检测
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("检测到: %v, 严重程度: %d\n", r.Detected, r.Severity)

    // 全量检测
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### Deteksi Permintaan HTTP

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("攻击检测: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### Konfigurasi Validator HTTP

```go
// 方法校验
e.Register(&httpval.Method{})

// 请求体大小限制
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 检查
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（自动封禁：5次/60s → 封禁15分钟）
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// 攻击发生时记录
blocked, _ := bl.RecordAttack(clientIP)
```

### Konfigurasi Keamanan Sesi

Paket `session` digunakan langsung sebagai middleware, tanpa melalui `Engine`. Penyimpanan perlu disiapkan aplikasi sendiri (implementasi memori tersedia secara default, dapat diganti dengan Redis dll):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // 可选：接入 GeoIP，用于识别跨国家登录

// 登录成功后绑定会话（token 由你的登录流程生成）
// 异地登录检测：比对该用户历史登录网段，出现新网段即告警
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // 绑定 token → IP 网段 / UA / 设备指纹
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// 保护路由：命中劫持或异地登录直接返回 401
mux.Handle("/api/", tr.Guard(apiHandler))

// 或只做检测、自行决定处置
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// 登出
tr.Revoke(token)
```

Deteksi manipulasi data: klien dan server berbagi kunci rahasia, klien menandatangani parameter, server menghitung ulang untuk verifikasi:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // 第二个参数用于拦截签名重放，可为 nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // 客户端：随参数一起提交

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` dinonaktifkan secara default: `X-Forwarded-For` / `X-Real-IP` dapat dikendalikan klien, aktifkan hanya di belakang reverse proxy sendiri.
> `FailClosed` dinonaktifkan secara default (lolos saat penyimpanan gagal, konsisten dengan `IPBlacklist`); sebaiknya aktifkan untuk bisnis yang sensitif terhadap sesi.

### Detektor Kustom

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "检测到恶意内容",
    }
}

e.Register(&MyDetector{})
```

### Dokumentasi Terkait

- [Dokumentasi API](api.md) — tipe inti, antarmuka Detector/Engine, antarmuka backend penyimpanan, validator HTTP
- [Spesifikasi Desain](specs/2026-07-29-attack-detection-design.md) — struktur paket, katalog detektor
- [Rencana Implementasi](plans/2026-07-29-attack-detection-plan.md) — rencana tugas bertahap dan perbandingan deviasi implementasi
- [Laporan Code Review](reports/2026-07-29-code-review-report.md) — perbaikan Bug, cakupan pengujian, evaluasi arsitektur

---

## Dokumen Multibahasa

| Bahasa | Dokumen |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [README.md](README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

Indeks semua terjemahan: [docs/i18n/README.md](../README.md)

---

## Dukungan Donasi

Jika proyek ini bermanfaat bagi Anda, silakan berikan dukungan:

| Metode | Kode QR |
|------|--------|
| Alipay | ![支付宝](images/alipay.png) |
| WeChat Pay | ![微信支付](images/weixinpay.png) |

### Donasi Transfer Global (Transfer Bank)

**Informasi Penerima**

- Nama Penerima: WANG KEXUN
- Nomor Rekening Penerima: 881015918251

**Bank Penerima (ZA Bank)**

- Kode SWIFT: `AABLHKHHXXX`
- Nama Bank: ZA Bank Limited
- Nomor Bank: 387
- Alamat Bank: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Bank Agen Transfer Lintas Batas (jika diperlukan)**

> Harap diperhatikan, ini adalah informasi bank agen transfer lintas batas (bank perantara), bukan informasi bank penerima. Silakan tanyakan kepada bank pengirim apakah informasi bank agen transfer lintas batas diperlukan.

- Bank agen untuk transfer masuk HKD, CNY, dan USD adalah Citibank:
  - Nama Bank: Citibank N.A. Hong Kong
  - Kode SWIFT: `CITIHKHXXXX`
  - Nomor Bank: 006
  - Nama Cabang: Hong Kong Branch
  - Nomor Cabang: 391
  - Alamat Bank: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- Bank agen untuk mata uang lainnya adalah BNY Mellon:
  - Nama Bank: THE BANK OF NEW YORK MELLON
  - Kode SWIFT: `IRVTUS3NXXX`
  - Alamat Bank: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
