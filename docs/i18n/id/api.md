# Security Go — Dokumentasi API

Dokumen ini merangkum seluruh API publik `security-go`: tipe inti, antarmuka `Detector`, registry `Engine`, antarmuka backend penyimpanan, dan konstruktor validator HTTP.

## Tipe Inti

### Result

Struktur hasil deteksi, dikembalikan oleh setiap detektor:

```go
type Result struct {
    Name     string                 // 检测器名称
    Detected bool                   // 是否检测到攻击
    Message  string                 // 结果说明
    Severity Severity               // 严重程度
    Details  map[string]interface{} // 附加细节
}
```

### Severity

Tingkat keparahan:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Antarmuka Detector

Semua detektor harus mengimplementasikan antarmuka ini:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Registry Engine

`Engine` adalah titik masuk terpadu, mendaftarkan dan mengelola detektor berdasarkan nama:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` secara otomatis mengumpulkan URL, Query, Headers, dan Cookies dari permintaan sebagai input. Setiap input dipindai ulang setelah didekode URL, sehingga muatan terenkode seperti `%3Cscript%3E` tidak dapat melewati deteksi.

## Titik Masuk Registrasi

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## Antarmuka Backend Penyimpanan

`httpval.IPBlacklist` menggunakan penyimpanan yang dapat dipasang melalui antarmuka ini:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

Implementasi:

| Backend | Keterangan |
|------|------|
| `storage.NewMemory()` | Implementasi memori, `sync.Mutex` + map, pembersihan otomatis entri kedaluwarsa setiap 30 detik |
| `storage.NewFile(path)` | Persistensi file JSON, penyimpanan otomatis setiap 30 detik + flush saat Close |
| `storage/redis` | Submodul Redis, Pipeline Incr + TTL, memerlukan `go-redis/v9` |

## Validator HTTP

```go
// 校验 HTTP 方法白名单
e.Register(&httpval.Method{})

// 请求体大小限制（默认 10MB）
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单（空白名单 = 拒绝所有）
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 校验（跨域请求检查 Origin 与 Host 匹配）
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（窗口内 N 次攻击自动封禁，默认 5次/60s → 封禁15分钟）
bl := httpval.NewIPBlacklist(mem) // mem 为任意 storage.Backend 实现
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### Kedalaman Penyarangan JSON & Atribut Cookie

| Konstruktor | Deskripsi |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Memindai body JSON secara streaming: melaporkan `nested_depth` saat kedalaman (bawaan 32) atau jumlah elemen terlampaui. JSON tidak valid atau terpotong tidak pernah cocok |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Memvalidasi satu `Set-Cookie`: atribut hilang, nilai terlalu panjang (`MaxValueLen`), nilai kosong (`RequireNonEmpty`) |

## Keamanan Sesi

Paket `session` mendeteksi **klien dibajak**, **manipulasi data**, **login dari lokasi lain**. Paket ini memerlukan `*http.Request` lengkap (token, IP klien, User-Agent) serta penyimpanan dan kunci yang disiapkan aplikasi, sehingga tidak didaftarkan ke `Engine` dan dipanggil langsung sebagai middleware/fungsi.

### Antarmuka Store

Pengikatan sesi tidak dapat diekspresikan dengan `storage.Backend` (hanya berisi penghitung dan blokir), sehingga `session` menyediakan antarmuka kecil tersendiri:

```go
type Store interface {
    Save(key string, value []byte, ttl time.Duration) error
    Load(key string) ([]byte, error)   // 不存在或已过期返回 (nil, nil)
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // 内存实现，30s 清理过期条目，Close 停止清理
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // 建立会话时的客户端 IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // 设备指纹（X-Device-Fingerprint 头）
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // 每次 Check 滑动续期
}
```

### Tracker

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // 会话生命周期，默认 30m，每次 Check 滑动续期
    SubnetBits        int                        // 同地判定前缀，默认 24（IPv6 自动 +24）
    CountryOf         func(ip string) string     // 可选 GeoIP 钩子；为 nil 时跳过国家判定
    KnownNets         int                        // Observe 每用户保留的登录网段数，默认 8
    KnownNetTTL       time.Duration              // 登录网段保留时长，默认 90 天
    TokenSource       func(*http.Request) string // 默认 DefaultTokenSource
    TrustProxyHeaders bool                       // 默认 false
    FailClosed        bool                       // 默认 false
    MaxLockout        time.Duration              // 每次锁定翻倍的上限，默认 24h
    BackoffWindow     time.Duration              // 升级计数的保留时长，默认 24h
    StuffingLimit     int                        // 同一 IP 允许失败的不同身份数上限，默认 10
}
```

| Metode | Keterangan |
|------|------|
| `NewTracker(store) *Tracker` | Membuat dan mengisi nilai default |
| `Issue(token, r) error` | Setelah login berhasil, mengikat token → subnet IP / UA / sidik jari; token kosong mengembalikan error |
| `Check(r) *Result` | Validasi setiap permintaan, mengembalikan `Detected: true` saat terdeteksi; memperpanjang secara sliding saat lolos |
| `Observe(user, r) *Result` | Saat login membandingkan subnet historis pengguna tersebut, memicu peringatan saat muncul subnet baru; login pertama tanpa baseline tidak memicu peringatan |
| `Guard(http.Handler) http.Handler` | Pembungkus middleware, mengembalikan 401 saat `Check` terdeteksi |
| `Revoke(token) error` | Logout, sesi langsung tidak berlaku |
| `DefaultTokenSource(r) string` | Mengambil `Authorization: Bearer <token>`, lalu Cookie `session` |
| `RecordFailure(identity, r) error` | Menghitung satu login gagal (identity adalah kunci autentikasi seperti nama pengguna, r menyediakan IP klien). Saat mencapai `Failures` (bawaan 5 dalam 5 menit) identitas terkunci, berlipat dua tiap kali hingga `MaxLockout` (bawaan 24 jam) |
| `CheckLogin(identity, r) *Result` | Pemeriksaan awal percobaan login: `token_locked` bila identitas terkunci, `credential_stuffing` bila IP klien sudah gagal terhadap `StuffingLimit` (bawaan 10) identitas berbeda — keduanya Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware untuk endpoint autentikasi: 429 dengan `Retry-After` saat terpicu; setelah handler, 401 dihitung gagal dan 2xx mereset hitungan |
| `IsLocked(token) (bool, time.Time)` | Apakah token terkunci dan sampai kapan; galat penyimpanan dibaca sebagai tidak terkunci |
| `ClearFailures(token) error` | Mereset hitungan kegagalan setelah login berhasil (kunci berjalan dengan pengatur waktunya sendiri) |

Nilai `Details["reason"]`:

| reason | Kondisi pemicu | Tingkat keparahan |
|--------|---------|---------|
| `missing_token` | Permintaan tidak membawa token | High |
| `unknown_token` | token belum diterbitkan, sudah di-`Revoke`, atau sudah kedaluwarsa | High |
| `token_locked` | Ambang kegagalan tercapai dalam jendela waktu, token terkunci | Critical |
| `credential_stuffing` | Satu IP gagal terhadap `StuffingLimit` identitas berbeda dalam jendela waktu | Critical |
| `client_hijack` | UA berubah, atau sidik jari perangkat berubah | Critical |
| `remote_login` | `CountryOf` menilai lintas negara (Critical) / IP lintas subnet (High), digunakan bersama oleh `Check` dan `Observe` | Critical / High |
| `store_error` | Pembacaan penyimpanan gagal dan `FailClosed = true` | High |

> `TrustProxyHeaders` dinonaktifkan secara default: `X-Forwarded-For` / `X-Real-IP` dapat dikendalikan klien; setelah diaktifkan, penyerang dapat memalsukan IP yang terikat. Aktifkan hanya di belakang reverse proxy sendiri.
> `FailClosed` dinonaktifkan secara default (lolos saat penyimpanan gagal), konsisten dengan `httpval.IPBlacklist`. Kunci penyimpanan adalah SHA-256 dari token, kebocoran penyimpanan tidak langsung menghasilkan token yang dapat dipakai.

### Signer

```go
type Signer struct {
    Secret  []byte           // 共享 HMAC 密钥，用 crypto/rand 生成
    MaxSkew time.Duration    // 时间戳允许偏差，默认 5m
    Nonces  storage.Backend  // 可选：非空时用窗口计数拦截签名重放（可跨实例，复用 Redis）
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // 参数被改动/密钥不符/超时/重放
```

Parameter dinormalisasi dengan `url.Values.Encode()` (urut + escape), urutan map tidak memengaruhi hasil. Urutan verifikasi adalah timestamp → tanda tangan → penghitung nonce, sehingga tanda tangan palsu tidak dapat menghabiskan nonce yang sah; saat `Nonces` bernilai nil, pembatasan replay hanya mengandalkan jendela timestamp.

Nilai `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Contoh Detektor Kustom

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

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
