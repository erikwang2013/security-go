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

`DetectRequest` স্বয়ংক্রিয়ভাবে রিকোয়েস্টের URL, Query, Headers, Cookies সংগ্রহ করে ইনপুট হিসেবে ব্যবহার করে।

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
