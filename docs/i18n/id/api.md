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

`DetectRequest` secara otomatis mengumpulkan URL, Query, Headers, dan Cookies dari permintaan sebagai input.

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
