# Security Go — Dokumentasi API

Dokumen ini merangkum seluruh API publik `security-go`: tipe inti, antarmuka `Detector`, registry `Engine`, antarmuka backend penyimpanan, dan konstruktor validator HTTP.

## Tipe Inti

### Result

Struktur hasil deteksi, dikembalikan oleh setiap detektor:

```go
type Result struct {
    Name     string                 // Nama detektor
    Detected bool                   // Apakah serangan terdeteksi
    Message  string                 // Deskripsi hasil
    Severity Severity               // Tingkat keparahan
    Details  map[string]interface{} // Detail tambahan
}
```

### Severity

Tingkat keparahan:

```go
type Severity int

const (
    SeverityLow      Severity = iota // Risiko rendah
    SeverityMedium                   // Risiko sedang
    SeverityHigh                     // Risiko tinggi
    SeverityCritical                 // Kritis
)
```

## Antarmuka Detector

Semua detektor harus mengimplementasikan antarmuka ini:

```go
type Detector interface {
    Name() string                // Nama unik detektor
    Detect(input string) *Result // Menjalankan deteksi pada input, mengembalikan hasil
}
```

## Registry Engine

`Engine` adalah titik masuk terpadu, mendaftarkan dan mengelola detektor berdasarkan nama:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // Membuat Engine kosong
func (e *Engine) Register(d Detector)             // Mendaftarkan detektor
func (e *Engine) Detect(name, input string) *Result // Mendeteksi satu input berdasarkan nama
func (e *Engine) DetectAll(input string) []*Result  // Deteksi menyeluruh (hanya mengembalikan Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // Mendeteksi permintaan HTTP lengkap
```

`DetectRequest` secara otomatis mengumpulkan URL, Query, Headers, dan Cookies dari permintaan sebagai input. Setiap input dipindai ulang setelah didekode URL, sehingga muatan terenkode seperti `%3Cscript%3E` tidak dapat melewati deteksi.

## Titik Masuk Registrasi

```go
// Paket all mendaftarkan semua detektor tanpa konfigurasi sekaligus (27)
all.RegisterAll(engine)
```

## Fungsi Pembantu

```go
// FirstMatch mengembalikan string pola pertama yang cocok dengan input; jika tidak ada yang cocok mengembalikan ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Agar detektor kustom dapat memakai ulang pola prakompilasi bawaan, tanpa mengompilasi ulang regex.

## Antarmuka Backend Penyimpanan

`httpval.IPBlacklist` menggunakan penyimpanan yang dapat dipasang melalui antarmuka ini:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // Menambah penghitung jendela +1
    Get(key string) (int, error)                          // Membaca penghitung
    Block(key string, duration time.Duration) error       // Memblokir selama durasi tertentu
    IsBlocked(key string) (bool, error)                   // Memeriksa apakah kunci sudah diblokir
    Close() error                                         // Menutup dan melepaskan sumber daya
}
```

Implementasi:

| Backend | Keterangan |
|------|------|
| `storage.NewMemory() *Memory` | Implementasi memori, `sync.Mutex` + map, pembersihan otomatis entri kedaluwarsa setiap 30 detik |
| `storage.NewFile(path) (*File, error)` | Persistensi file JSON, penyimpanan otomatis setiap 30 detik + flush saat Close |
| `redis.New(addr, password string, db int) *Backend` | Submodul Redis, Pipeline Incr + TTL, memerlukan `go-redis/v9` |

## Validator HTTP

```go
// Validasi whitelist metode HTTP
e.Register(&httpval.Method{})

// Batas ukuran body permintaan (bawaan 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Whitelist Content-Type (daftar kosong = tolak semua)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Validasi Origin CSRF (permintaan lintas origin harus cocok dengan Host)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// Daftar hitam IP (blokir otomatis setelah N serangan dalam jendela, bawaan 5/60s → blokir 15 menit)
bl := httpval.NewIPBlacklist(mem) // mem adalah sembarang implementasi storage.Backend
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
    Load(key string) ([]byte, error)   // Mengembalikan (nil, nil) jika tidak ada atau kedaluwarsa
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // Implementasi memori, membersihkan entri kedaluwarsa setiap 30 detik, Close menghentikan pembersihan
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // IP klien saat sesi dibuat
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // Sidik jari perangkat (header X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // Diperpanjang secara sliding setiap Check
}
```

### Tracker

Nama detektor `session_guard` (lihat `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // Masa hidup sesi, bawaan 30m, diperpanjang sliding setiap Check
    SubnetBits        int                        // Prefiks penentuan lokasi sama, bawaan 24 (IPv6 otomatis +24)
    CountryOf         func(ip string) string     // Hook GeoIP opsional; jika nil, pemeriksaan negara dilewati
    KnownNets         int                        // Jumlah subnet login yang disimpan per pengguna oleh Observe, bawaan 8
    KnownNetTTL       time.Duration              // Durasi penyimpanan subnet login, bawaan 90 hari
    TokenSource       func(*http.Request) string // Bawaan DefaultTokenSource
    TrustProxyHeaders bool                       // Bawaan false
    FailClosed        bool                       // Bawaan false
    Failures          int                        // Ambang kegagalan yang mengunci token dalam jendela, bawaan 5
    FailureWindow     time.Duration              // Durasi penyimpanan hitungan kegagalan, di luar itu tidak dihitung, bawaan 5m
    Lockout           time.Duration              // Durasi kunci saat pertama mencapai ambang, berlipat dua tiap kali, bawaan 15m
    MaxLockout        time.Duration              // Batas atas penggandaan tiap penguncian, bawaan 24h
    BackoffWindow     time.Duration              // Durasi penyimpanan hitungan eskalasi, bawaan 24h
    StuffingLimit     int                        // Batas jumlah identitas berbeda yang gagal dari IP yang sama, bawaan 10
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

Nama detektor `data_tamper` (lihat `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // Kunci HMAC bersama, buat dengan crypto/rand
    MaxSkew time.Duration    // Selisih stempel waktu yang diizinkan, bawaan 5m
    Nonces  storage.Backend  // Opsional: jika tidak nil, penghitung jendela mencegat replay tanda tangan (bisa lintas instans, memakai ulang Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // Parameter diubah/kunci tidak cocok/waktu habis/replay
```

Parameter dinormalisasi dengan `url.Values.Encode()` (urut + escape), urutan map tidak memengaruhi hasil. Urutan verifikasi adalah timestamp → tanda tangan → penghitung nonce, sehingga tanda tangan palsu tidak dapat menghabiskan nonce yang sah; saat `Nonces` bernilai nil, pembatasan replay hanya mengandalkan jendela timestamp.

Nilai `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Fungsi Pembantu Unggah Berkas

Selain didaftarkan sebagai detektor, deteksi unggahan juga mengekspor dua fungsi pembantu yang bisa dipanggil langsung:

```go
// HasMaliciousExt menentukan apakah ekstensi nama berkas tidak ada di whitelist (15 jenis); tanpa ekstensi mengembalikan true
func HasMaliciousExt(filename string) bool

// CheckExtension seasal dengan di atas, tetapi mengembalikan *Result lengkap (beserta tingkat keparahan dan deskripsi)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Untuk validasi awal yang cepat sebelum berkas ditulis ke disk, tanpa membuat `Engine`.

## Maskot Proyek

Paket `pet` menyematkan SVG maskot proyek, Sentinel Gopher, saat kompilasi melalui `go:embed` — tanpa dependensi pihak ketiga dan tanpa membaca berkas saat runtime:

```go
func SVG() []byte         // Byte SVG mentah; slice dibagi, pemanggil tidak boleh mengubahnya
func Handler() http.Handler // Disajikan sebagai image/svg+xml, Cache-Control satu hari
func Banner() string      // Banner teks polos yang ramah terminal, dengan baris baru di akhir
```

```go
log.Println(pet.Banner())              // Dicetak saat startup
http.Handle("/pet.svg", pet.Handler()) // Dipasang ke rute debug
```

Di dalamnya `Handler` memakai `http.ServeContent`, sehingga membawa `Content-Length` serta mendukung `Range` dan `HEAD`; `w.Write` langsung akan melewati buffer sniff 2 KiB milik `net/http` dan berubah menjadi respons chunked.

## Contoh Detektor Kustom

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "konten berbahaya terdeteksi",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
