# Security Go — API Reference

This document summarizes all public APIs of `security-go`: core types, the `Detector` interface, the `Engine` registry, storage backend interfaces, and HTTP validator constructors.

## Core Types

### Result

The detection result struct, returned by every detector:

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

Severity levels:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector Interface

All detectors must implement this interface:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine Registry

`Engine` is the unified entry point that registers and manages detectors by name:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` automatically collects the request's URL, Query, Headers, and Cookies as input. Each input is also scanned after URL-decoding, so encoded payloads such as `%3Cscript%3E` cannot bypass detection.

## Registration Entry Point

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## Storage Backend Interface

`httpval.IPBlacklist` uses pluggable storage through this interface:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

Implementations:

| Backend | Description |
|------|------|
| `storage.NewMemory()` | In-memory implementation, `sync.Mutex` + map, auto-cleans expired entries every 30s |
| `storage.NewFile(path)` | JSON file persistence, auto-save every 30s + flush on Close |
| `storage/redis` | Redis submodule, Pipeline Incr + TTL, requires `go-redis/v9` |

## HTTP Validators

```go
// HTTP 方法白名单校验
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

### JSON Nesting Depth & Cookie Attributes

| Constructor | Description |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Streams a JSON body: reports `nested_depth` when nesting depth (default 32) or element count is exceeded. Non-JSON and truncated JSON never match |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Validates one `Set-Cookie`: missing attributes, overlong value (`MaxValueLen`), empty value (`RequireNonEmpty`) |

## Session Security

The `session` package detects **client hijacking**, **data tampering**, and **remote login**. It needs the complete `*http.Request` (token, client IP, User-Agent) plus application-provided storage and a secret key, so it is not registered with the `Engine` and is called directly as middleware/functions.

### Store interface

A session binding cannot be expressed with `storage.Backend` (counts and bans only), so `session` ships its own small interface:

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

| Method | Description |
|------|------|
| `NewTracker(store) *Tracker` | Creates a tracker and fills in the defaults |
| `Issue(token, r) error` | Binds the token to the IP subnet / UA / fingerprint after a successful login; an empty token returns an error |
| `Check(r) *Result` | Validates on every request and returns `Detected: true` on a hit; slide-renews on pass |
| `Observe(user, r) *Result` | At login, compares against the user's historical login networks and alerts on a new subnet; no alert on the first login (no baseline) |
| `Guard(http.Handler) http.Handler` | Middleware wrapper; returns 401 as soon as `Check` hits |
| `Revoke(token) error` | Logout; the session becomes invalid immediately |
| `DefaultTokenSource(r) string` | Reads `Authorization: Bearer <token>`, then the `session` cookie |
| `RecordFailure(identity, r) error` | Counts one failed login (identity is the authentication key such as a username; r supplies the client IP). Reaching `Failures` (default 5 in 5 minutes) locks the identity, doubling each episode up to `MaxLockout` (default 24h) |
| `CheckLogin(identity, r) *Result` | Pre-flight for a login attempt: `token_locked` when the identity is locked, `credential_stuffing` when the client IP has already failed against `StuffingLimit` (default 10) distinct identities — both Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware for an authentication endpoint: 429 with `Retry-After` when it fires; a 401 afterwards counts as a failure and a 2xx clears the counter |
| `IsLocked(token) (bool, time.Time)` | Whether the token is locked and until when; a store error reads as unlocked |
| `ClearFailures(token) error` | Resets the failure count on a successful login (a lockout runs its own timer and is not cleared) |

`Details["reason"]` values:

| reason | Trigger | Severity |
|------|------|------|
| `missing_token` | The request carries no token | High |
| `unknown_token` | The token was never issued, has been `Revoke`d, or has expired | High |
| `token_locked` | Failure threshold reached inside the window, token locked out | Critical |
| `credential_stuffing` | One client IP failed against `StuffingLimit` distinct identities inside the window | Critical |
| `client_hijack` | The UA changed, or the device fingerprint changed | Critical |
| `remote_login` | `CountryOf` judges a country change (Critical) / an IP subnet change (High); shared by `Check` and `Observe` | Critical / High |
| `store_error` | The storage read failed and `FailClosed = true` | High |

> `TrustProxyHeaders` is disabled by default: `X-Forwarded-For` / `X-Real-IP` are client-controllable, and enabling it lets a hijacker forge the bound IP. Enable it only behind your own reverse proxy.
> `FailClosed` is disabled by default (requests pass through on storage failure), consistent with `httpval.IPBlacklist`. Storage keys are the SHA-256 of the token, so a storage leak does not directly yield a usable token.

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

Parameters are canonicalized with `url.Values.Encode()` (sorted + escaped), so map ordering does not affect the result. Verification runs in the order timestamp → signature → nonce counter, so a forged signature cannot consume a legitimate nonce; when `Nonces` is nil, only the timestamp window limits replay.

`Details["reason"]` values: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Custom Detector Example

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
