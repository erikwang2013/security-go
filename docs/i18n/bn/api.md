# Security Go — API ইন্টারফেস ডকুমেন্ট

এই ডকুমেন্টে `security-go`-এর সব পাবলিক API ইন্টারফেস সংক্ষিপ্ত করা হয়েছে: কোর টাইপ, `Detector` ইন্টারফেস, `Engine` রেজিস্ট্রি, স্টোরেজ ব্যাকএন্ড ইন্টারফেস ও HTTP ভ্যালিডেটর কনস্ট্রাক্টর।

## কোর টাইপ

### Result

ডিটেকশন ফলাফল স্ট্রাকচার, প্রতিটি ডিটেক্টর থেকে রিটার্ন হয়:

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

তীব্রতার স্তর:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector ইন্টারফেস

সব ডিটেক্টরকে এই ইন্টারফেস বাস্তবায়ন করতে হবে:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine রেজিস্ট্রি

`Engine` হলো ইউনিফাইড এন্ট্রি পয়েন্ট, যা নাম অনুযায়ী ডিটেক্টর নিবন্ধন ও পরিচালনা করে:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` স্বয়ংক্রিয়ভাবে রিকোয়েস্টের URL, Query, Headers, Cookies সংগ্রহ করে ইনপুট হিসেবে ব্যবহার করে। প্রতিটি ইনপুট URL-ডিকোড করার পর আবার স্ক্যান করা হয়, তাই `%3Cscript%3E`-এর মতো এনকোডেড পেলোড এড়াতে পারে না।

## রেজিস্ট্রেশন এন্ট্রি পয়েন্ট

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## স্টোরেজ ব্যাকএন্ড ইন্টারফেস

`httpval.IPBlacklist` এই ইন্টারফেসের মাধ্যমে প্লাগেবল স্টোরেজ ব্যবহার করে:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

বাস্তবায়ন:

| ব্যাকএন্ড | বর্ণনা |
|-----------|--------|
| `storage.NewMemory()` | মেমোরি ইমপ্লিমেন্টেশন, `sync.Mutex` + map, 30s পর মেয়াদোত্তীর্ণ এন্ট্রি স্বয়ংক্রিয় পরিষ্কার |
| `storage.NewFile(path)` | JSON ফাইল পার্সিস্টেন্স, 30s পর স্বয়ংক্রিয় সেভ + Close করার সময় flush |
| `storage/redis` | Redis সাবমডিউল, Pipeline Incr + TTL, `go-redis/v9` প্রয়োজন |

## HTTP ভ্যালিডেটর

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

### JSON নেস্টিং ডেপথ ও Cookie অ্যাট্রিবিউট

| কনস্ট্রাক্টর | বর্ণনা |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | JSON বডি স্ট্রিম স্ক্যান: নেস্টিং গভীরতা (ডিফল্ট 32) বা এলিমেন্ট সংখ্যা ছাড়ালে `nested_depth` রিপোর্ট; অবৈধ বা কাটা JSON কখনও মেলে না |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | একটি `Set-Cookie` যাচাই: অনুপস্থিত অ্যাট্রিবিউট, অতিরিক্ত দীর্ঘ মান (`MaxValueLen`), খালি মান (`RequireNonEmpty`) |

## সেশন নিরাপত্তা

`session` প্যাকেজ **ক্লায়েন্ট হাইজ্যাক**, **ডেটা ট্যাম্পারিং**, **দূরবর্তী লগইন** সনাক্ত করে। এতে সম্পূর্ণ `*http.Request` (token, ক্লায়েন্ট IP, User-Agent) এবং অ্যাপ্লিকেশনের নিজস্ব স্টোরেজ ও কী প্রয়োজন, তাই এটি `Engine`-এ রেজিস্টার হয় না, সরাসরি মিডলওয়্যার/ফাংশন হিসেবে আহ্বান করা হয়।

### Store ইন্টারফেস

সেশন বাইন্ডিং `storage.Backend` (যা শুধু কাউন্ট ও ব্লক সমর্থন করে) দিয়ে প্রকাশ করা যায় না, তাই `session` নিজস্ব একটি ছোট ইন্টারফেস নিয়ে আসে:

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

| মেথড | বর্ণনা |
|------|------|
| `NewTracker(store) *Tracker` | তৈরি করে ডিফল্ট মান পূরণ করে |
| `Issue(token, r) error` | লগইন সফল হলে token → IP সাবনেট / UA / ফিঙ্গারপ্রিন্ট বাইন্ড করে; খালি token হলে এরর রিটার্ন করে |
| `Check(r) *Result` | প্রতি রিকোয়েস্টে যাচাই করে, সনাক্ত হলে `Detected: true` রিটার্ন করে; পাস হলে সেশন স্লাইডিং রিনিউ হয় |
| `Observe(user, r) *Result` | লগইনের সময় ব্যবহারকারীর পূর্ববর্তী লগইন সাবনেটের সাথে তুলনা করে, নতুন সাবনেট দেখা গেলে সতর্ক করে; প্রথম লগইনে বেসলাইন না থাকলে সতর্ক করে না |
| `Guard(http.Handler) http.Handler` | মিডলওয়্যার র‍্যাপার, `Check` সনাক্ত করলে 401 রিটার্ন করে |
| `Revoke(token) error` | লগআউট, সেশন তাৎক্ষণিক বাতিল হয় |
| `DefaultTokenSource(r) string` | `Authorization: Bearer <token>` নেয়, তারপর `session` কুকি |
| `RecordFailure(identity, r) error` | একটি ব্যর্থ লগইন গণনা (identity হলো প্রমাণীকরণ কী যেমন ব্যবহারকারী নাম, r ক্লায়েন্ট IP দেয়); উইন্ডোর মধ্যে `Failures` (ডিফল্ট ৫, ৫ মিনিটে) ছুঁলে আইডেন্টিটি লক হয়, প্রতিবার দ্বিগুণ হয়ে `MaxLockout` (ডিফল্ট ২৪ ঘণ্টা) পর্যন্ত |
| `CheckLogin(identity, r) *Result` | লগইন প্রচেষ্টার প্রাক-পরীক্ষা: আইডেন্টিটি লক থাকলে `token_locked`, ক্লায়েন্ট IP `StuffingLimit` (ডিফল্ট ১০) টি ভিন্ন আইডেন্টিটিতে ব্যর্থ হলে `credential_stuffing` — দুটোই Critical |
| `GuardLogin(next, identity) http.Handler` | প্রমাণীকরণ এন্ডপয়েন্টের মিডলওয়্যার: মিললে `Retry-After` সহ 429; হ্যান্ডলারের পরে 401 ব্যর্থতা গণ্য হয়, 2xx গণনা শূন্য করে |
| `IsLocked(token) (bool, time.Time)` | টোকেন লক করা আছে কি না এবং কখন পর্যন্ত; স্টোর ত্রুটি আনলকড হিসেবে পড়া হয় |
| `ClearFailures(token) error` | সফল লগইনে ব্যর্থতার গণনা শূন্য করে (লক নিজের টাইমারে চলে, মুছে যায় না) |

`Details["reason"]`-এর মান:

| reason | ট্রিগার শর্ত | তীব্রতা |
|--------|---------|---------|
| `missing_token` | রিকোয়েস্টে token নেই | High |
| `unknown_token` | token ইস্যু হয়নি, `Revoke` হয়েছে বা মেয়াদোত্তীর্ণ | High |
| `token_locked` | উইন্ডোর মধ্যে ব্যর্থতার সীমা ছোঁয়া, টোকেন লক | Critical |
| `credential_stuffing` | উইন্ডোর মধ্যে একটি IP `StuffingLimit` টি ভিন্ন আইডেন্টিটিতে ব্যর্থ | Critical |
| `client_hijack` | UA পরিবর্তন, বা ডিভাইস ফিঙ্গারপ্রিন্ট পরিবর্তন | Critical |
| `remote_login` | `CountryOf` দেশ পরিবর্তন নির্ণয় করে (Critical) / IP সাবনেট পরিবর্তন (High), `Check` ও `Observe` উভয়ে ব্যবহৃত | Critical / High |
| `store_error` | স্টোরেজ পড়তে ব্যর্থ এবং `FailClosed = true` | High |

> `TrustProxyHeaders` ডিফল্টভাবে বন্ধ: `X-Forwarded-For` / `X-Real-IP` ক্লায়েন্টের নিয়ন্ত্রণে, চালু করলে হাইজ্যাকার বাইন্ড করা IP জাল করতে পারে। কেবল নিজের রিভার্স প্রক্সির পেছনে চালু করুন।
> `FailClosed` ডিফল্টভাবে বন্ধ (স্টোরেজ ব্যর্থ হলে অনুমোদন), `httpval.IPBlacklist`-এর সাথে সামঞ্জস্যপূর্ণ। স্টোরেজ কী হলো token-এর SHA-256, তাই স্টোরেজ ফাঁস হলেও সরাসরি ব্যবহারযোগ্য token পাওয়া যায় না।

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

প্যারামিটার `url.Values.Encode()` দিয়ে ক্যানোনিকালাইজ করা হয় (সাজানো + এস্কেপ), map-এর ক্রম ফলাফলকে প্রভাবিত করে না। যাচাইয়ের ক্রম টাইমস্ট্যাম্প → সিগনেচার → nonce কাউন্টার, তাই জাল সিগনেচার বৈধ nonce খরচ করতে পারে না; `Nonces` nil হলে কেবল টাইমস্ট্যাম্প উইন্ডো দিয়ে রিপ্লে সীমিত করা যায়।

`Details["reason"]`-এর মান: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High)।

## কাস্টম ডিটেক্টর উদাহরণ

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
