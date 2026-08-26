# Attack Detection Package — Implementation Plan

> **Untuk agen pekerja:** SUB-KETERAMPILAN WAJIB: Gunakan superpowers:subagent-driven-development (disarankan) atau superpowers:executing-plans untuk mengimplementasikan rencana ini tugas demi tugas.

**Tujuan:** Membangun pustaka deteksi serangan murni Go dengan 32 detektor di 5 kategori, 3 backend penyimpanan yang dapat dipasang, dan registry Engine terpadu. **Status: Selesai (2026-07-29).**

**Arsitektur:** Desain antarmuka datar — setiap detektor mengimplementasikan `Detector` (Name + Detect). Pola regex pra-kompilasi. Engine menyediakan registry, pencarian berdasarkan nama, dan `DetectRequest` untuk pemindaian permintaan HTTP lengkap. RegisterAll berada di `all/all.go` (paket terpisah).

**Tumpukan Teknologi:** Go 1.21+, `regexp` stdlib + `net/http`, `go-redis` untuk backend Redis (submodul opsional di `storage/redis/`).

---

### Tugas 1: Inisialisasi Modul Go & Tipe Inti

**File:**
- Buat: `go.mod`
- Buat: `security.go`

- [x] **Langkah 1: Inisialisasi modul Go**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **Langkah 2: Buat security.go — Result, Severity, antarmuka Detector, Engine**

```go
package security

import "net/http"

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type Result struct {
	Name     string
	Detected bool
	Message  string
	Severity Severity
	Details  map[string]interface{}
}

type Detector interface {
	Name() string
	Detect(input string) *Result
}

type Engine struct {
	detectors map[string]Detector
}

func NewEngine() *Engine {
	return &Engine{detectors: make(map[string]Detector)}
}

func (e *Engine) Register(d Detector) {
	e.detectors[d.Name()] = d
}

func (e *Engine) Detect(name, input string) *Result {
	if d, ok := e.detectors[name]; ok {
		return d.Detect(input)
	}
	return nil
}

func (e *Engine) DetectAll(input string) []*Result {
	var results []*Result
	for _, d := range e.detectors {
		if r := d.Detect(input); r != nil && r.Detected {
			results = append(results, r)
		}
	}
	return results
}

func (e *Engine) DetectRequest(r *http.Request) []*Result {
	var results []*Result
	inputs := collectRequestInputs(r)
	for _, input := range inputs {
		results = append(results, e.DetectAll(input)...)
	}
	return results
}

func collectRequestInputs(r *http.Request) []string {
	var inputs []string
	inputs = append(inputs, r.URL.String())
	inputs = append(inputs, r.URL.Query().Encode())
	for key, vals := range r.Header {
		for _, v := range vals {
			inputs = append(inputs, key+": "+v)
		}
	}
	for _, c := range r.Cookies() {
		inputs = append(inputs, c.Name+"="+c.Value)
	}
	return inputs
}
```

- [x] **Langkah 3: Build** — `go build ./...`
- [x] **Langkah 4: Commit** — `feat: initialize Go module with core types and Engine`

---

### Tugas 2: Antarmuka Backend Penyimpanan & Memory

**File:**
- Buat: `storage/storage.go`
- Buat: `storage/memory.go`

- [x] **Langkah 1: storage/storage.go** — antarmuka Backend (Incr, Get, Block, IsBlocked, Close)
- [x] **Langkah 2: storage/memory.go** — implementasi berbasis sync.Map dengan goroutine reap TTL
- [x] **Langkah 3: Build** — `go build ./storage/...`
- [x] **Langkah 4: Commit** — `feat: add storage interface and memory backend`

---

### Tugas 3: Penyimpanan File & Redis

**File:**
- Buat: `storage/file.go`
- Buat: `storage/redis.go`
- Ubah: `go.mod` (tambahkan dependensi go-redis)

- [x] **Langkah 1: storage/file.go** — persistensi file JSON dengan flush lazy
- [x] **Langkah 2: storage/redis.go** — backend Redis menggunakan go-redis/v9
- [x] **Langkah 3: Build** — `go build ./storage/...`
- [x] **Langkah 4: Commit** — `feat: add file and redis storage backends`

---

### Tugas 4: Detektor Injeksi — XSS, SQL

**File:**
- Buat: `injection/xss.go`
- Buat: `injection/sql.go`

- [x] **Langkah 1: injection/xss.go** — pola `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS
- [x] **Langkah 2: injection/sql.go** — UNION SELECT (dengan bypass `/**/`), sleep/benchmark, blind boolean, enumerasi schema, stored proc
- [x] **Langkah 3: Build** — `go build ./injection/...`
- [x] **Langkah 4: Commit** — `feat: add XSS and SQL injection detectors`

---

### Tugas 5: Detektor Injeksi — Command, NoSQL, LDAP, XPATH

**File:**
- Buat: `injection/command.go`
- Buat: `injection/nosql.go`
- Buat: `injection/ldap.go`
- Buat: `injection/xpath.go`

- [x] **Langkah 1: injection/command.go** — backtick, `$()`, pipe, `/dev/tcp`, fungsi exec PHP
- [x] **Langkah 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, bypass autentikasi
- [x] **Langkah 3: injection/ldap.go** — operator filter `(`, `)`, `&`, `|`, `*`
- [x] **Langkah 4: injection/xpath.go** — bypass boolean, string-length, count
- [x] **Langkah 5: Build & Commit**

---

### Tugas 6: Detektor Injeksi — JNDI, SSI, GraphQL, SSTI

**File:**
- Buat: `injection/jndi.go`
- Buat: `injection/ssi.go`
- Buat: `injection/graphql.go`
- Buat: `injection/ssti.go`

- [x] **Langkah 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, protokol rmi/dns
- [x] **Langkah 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **Langkah 3: injection/graphql.go** — `__schema`, `__type`, query nested dalam, mutation
- [x] **Langkah 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **Langkah 5: Build & Commit**

---

### Tugas 7: Detektor Protokol — SSRF, XXE, Header Injection

**File:**
- Buat: `protocol/ssrf.go`
- Buat: `protocol/xxe.go`
- Buat: `protocol/header_injection.go`

- [x] **Langkah 1: protocol/ssrf.go** — IP internal, 169.254.169.254, IPv6 loopback, gopher/dict
- [x] **Langkah 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, entitas parameter, DOCTYPE
- [x] **Langkah 3: protocol/header_injection.go** — CRLF, injeksi Set-Cookie/Location
- [x] **Langkah 4: Build & Commit**

---

### Tugas 8: Detektor Protokol — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**File:**
- Buat: `protocol/host_header.go`
- Buat: `protocol/request_smuggling.go`
- Buat: `protocol/open_redirect.go`
- Buat: `protocol/cors.go`
- Buat: `protocol/websocket.go`
- Buat: `protocol/dns_rebinding.go`

- [x] **Langkah 1: Semua 6 detektor protokol** — satu file per detektor, pola regex pra-kompilasi
- [x] **Langkah 2: Build & Commit**

---

### Tugas 9: Detektor Validasi HTTP

**File:**
- Buat: `httpval/method.go`
- Buat: `httpval/body_size.go`
- Buat: `httpval/content_type.go`
- Buat: `httpval/csrf_origin.go`
- Buat: `httpval/ip_blacklist.go`

- [x] **Langkah 1: httpval/method.go** — daftar putih GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **Langkah 2: httpval/body_size.go** — pemeriksaan ukuran maksimum, default 10MB
- [x] **Langkah 3: httpval/content_type.go** — daftar putih MIME
- [x] **Langkah 4: httpval/csrf_origin.go** — pencocokan Origin lintas domain vs Host
- [x] **Langkah 5: httpval/ip_blacklist.go** — rate limit jendela (5/60s → blokir 15 menit), menggunakan storage.Backend
- [x] **Langkah 6: Build & Commit**

---

### Tugas 10: Detektor Data/Serialisasi

**File:**
- Buat: `data/deserialization.go`
- Buat: `data/csv_injection.go`
- Buat: `data/mail_header.go`
- Buat: `data/jwt_attack.go`
- Buat: `data/prototype_pollution.go`

- [x] **Langkah 1: data/deserialization.go** — PHP `O:数字:`, `C:数字:`, unserialize(), metode ajaib
- [x] **Langkah 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, prefiks rumus `+`, `-`
- [x] **Langkah 3: data/mail_header.go** — injeksi Bcc/Cc/From/To, MIME multipart
- [x] **Langkah 4: data/jwt_attack.go** — alg:none, path traversal kid, tanda tangan kosong (decoding struktural)
- [x] **Langkah 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **Langkah 6: Build & Commit**

---

### Tugas 11: Detektor File & Data Sensitif

**File:**
- Buat: `file/path_traversal.go`
- Buat: `file/upload.go`
- Buat: `file/data_leak.go`

- [x] **Langkah 1: file/path_traversal.go** — `../`, `..\\`, php://filter, null byte, bypass encoding URL
- [x] **Langkah 2: file/upload.go** — daftar putih ekstensi + pemindaian konten tag PHP
- [x] **Langkah 3: file/data_leak.go** — kartu kredit, kunci AWS, kunci privat, string koneksi DB, token API, JWT secret
- [x] **Langkah 4: Build & Commit**

---

### Tugas 12: Integrasi Engine — RegisterAll

**File:**
- Ubah: `security.go`

- [x] **Langkah 1: Tambahkan RegisterAll()** — mendaftarkan semua 32 detektor bawaan
- [x] **Langkah 2: Build** — `go build ./...`
- [x] **Langkah 3: Commit** — `feat: add RegisterAll for built-in detectors`

---

### Tugas 13: Pengujian

**File:**
- Buat: `security_test.go`
- Buat: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Buat: `protocol/ssrf_test.go`
- Buat: `file/path_traversal_test.go`, `data_leak_test.go`
- Buat: `data/jwt_attack_test.go`
- Buat: `storage/memory_test.go`

- [x] **Langkah 1: Tulis pengujian** — masing-masing dengan kasus uji positif dan negatif
- [x] **Langkah 2: Jalankan** — `go test ./... -v`
- [x] **Langkah 3: Commit** — `test: add core engine and detector tests`

---

### Tugas 14: Code Review Pasca-Implementasi & Perbaikan (2026-07-29)

- [x] **Code review menyeluruh** — 42 file sumber Go, 8 paket
- [x] **Perbaikan Bug #1** — `storage/file.go`: error serialisasi JSON diabaikan secara diam-diam → diubah menjadi memeriksa error dan mengembalikannya
- [x] **Perbaikan Bug #2** — `httpval/content_type.go`: AllowList kosong meloloskan semua Content-Type → default deny-all
- [x] **Perbaikan Bug #3** — `protocol/xxe.go`: `&[a-z]+;` salah mencocokkan entitas HTML legal → dipersempit menjadi daftar protokol berbahaya yang diketahui
- [x] **Lengkapi pengujian httpval** — 32 kasus uji, mencakup 5 detektor (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Pengujian menyeluruh** — `go test -count=1 ./...` 7/7 paket lolos, `go vet` nol peringatan

---

## Deviasi Aktual vs Rencana

| Rencana | Aktual | Alasan |
|------|------|------|
| RegisterAll di `security.go` | Paket terpisah `all/all.go` | Menghindari referensi sirkular; httpval bergantung pada storage tetapi detektor lain tidak |
| Redis di go.mod root | Submodul `storage/redis/` | Mengisolasi dependensi opsional |
| Receiver terpadu dengan pointer | Paket protocol menggunakan value receiver | ✅ Semuanya telah diubah ke pointer receiver di review v2 |
| Tugas 4-12 Build & Commit | Tidak di-commit bertahap | Semua kode diimplementasikan sekaligus |

## Ringkasan Cakupan Pengujian

| Paket | File Pengujian | Jumlah Uji |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (tidak ada) | 0 |

> Laporan lengkap lihat `docs/superpowers/reports/2026-07-29-code-review-report-v2.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
