# Security Go — API 接口文档

本文档汇总 `security-go` 的全部公开 API 接口：核心类型、`Detector` 接口、`Engine` 注册表、存储后端接口与 HTTP 校验器构造器。

## 核心类型

### Result

检测结果结构体，由每个检测器返回：

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

严重程度分级：

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector 接口

所有检测器必须实现此接口：

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine 注册表

`Engine` 是统一入口，按名称注册和管理检测器：

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` 自动收集请求的 URL、Query、Headers、Cookies 作为输入。

## 注册入口

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## 存储后端接口

`httpval.IPBlacklist` 通过该接口使用可插拔存储：

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

实现：

| 后端 | 说明 |
|------|------|
| `storage.NewMemory()` | 内存实现，`sync.Mutex` + map，30s 自动清理过期条目 |
| `storage.NewFile(path)` | JSON 文件持久化，30s 自动保存 + Close 时 flush |
| `storage/redis` | Redis 子模块，Pipeline Incr + TTL，需 `go-redis/v9` |

## HTTP 校验器

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

### JSON 嵌套深度与 Cookie 属性

| 构造器 | 说明 |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | 流式扫描 JSON 体：嵌套深度（默认 32）或元素数超限即报 `nested_depth`；非 JSON 与截断 JSON 永不命中 |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | 校验单个 `Set-Cookie`：缺失属性、值超长（`MaxValueLen`）、空值（`RequireNonEmpty`） |

## 会话安全

`session` 包检测**客户端被劫持**、**篡改数据**、**异地登录**。它需要完整的 `*http.Request`（token、客户端 IP、User-Agent）以及应用自备的存储与密钥，因此不注册进 `Engine`，直接作为中间件/函数调用。

### Store 接口

会话绑定无法用 `storage.Backend`（只有计数与封禁）表达，因此 `session` 自带一个小接口：

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
}
```

| 方法 | 说明 |
|------|------|
| `NewTracker(store) *Tracker` | 创建并填入默认值 |
| `Issue(token, r) error` | 登录成功后绑定 token → IP 网段 / UA / 指纹；空 token 返回错误 |
| `Check(r) *Result` | 逐请求校验，命中返回 `Detected: true`；通过时滑动续期 |
| `Observe(user, r) *Result` | 登录时比对该用户历史登录网段，出现新网段告警；首次登录无基线不告警 |
| `Guard(http.Handler) http.Handler` | 中间件包装，`Check` 命中即返回 401 |
| `Revoke(token) error` | 登出，会话立即失效 |
| `DefaultTokenSource(r) string` | 取 `Authorization: Bearer <token>`，其次 `session` Cookie |
| `RecordFailure(token) error` | 记录一次认证失败；窗口内累计达 `Failures`（默认 5 次 / 5 分钟）即写入锁定，`Lockout` 默认 15 分钟 |
| `IsLocked(token) (bool, time.Time)` | 是否处于锁定及解锁时间；存储故障按未锁定处理 |
| `ClearFailures(token) error` | 登录成功后清零失败计数（不清除锁定，锁定按自身计时） |

`Details["reason"]` 取值：

| reason | 触发条件 | 严重程度 |
|--------|---------|---------|
| `missing_token` | 请求未携带 token | High |
| `unknown_token` | token 未签发、已 `Revoke` 或已过期 | High |
| `token_locked` | 窗口内失败次数达阈值，token 被锁定 | Critical |
| `client_hijack` | UA 变化，或设备指纹变化 | Critical |
| `remote_login` | `CountryOf` 判定跨国家（Critical）/ IP 跨网段（High），`Check` 与 `Observe` 共用 | Critical / High |
| `store_error` | 存储读取失败且 `FailClosed = true` | High |

> `TrustProxyHeaders` 默认关闭：`X-Forwarded-For` / `X-Real-IP` 由客户端可控，开启后劫持者可伪造被绑定的 IP。仅在自有反向代理之后开启。
> `FailClosed` 默认关闭（存储故障时放行），与 `httpval.IPBlacklist` 一致。存储键为 token 的 SHA-256，存储泄露不会直接得到可用 token。

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

参数以 `url.Values.Encode()` 规范化（排序 + 转义），map 顺序不影响结果。校验顺序为时间戳 → 签名 → nonce 计数，因此伪造签名无法消耗合法 nonce；`Nonces` 为 nil 时只能靠时间戳窗口限制重放。

`Details["reason"]` 取值：`signer_not_configured`（Critical）、`signature_mismatch`（Critical）、`replay`（Critical）、`signature_malformed`、`timestamp_invalid`、`signature_expired`、`timestamp_in_future`（High）。

## 自定义检测器示例

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
