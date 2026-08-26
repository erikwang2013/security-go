# Security Go — API दस्तावेज़

यह दस्तावेज़ `security-go` के सभी सार्वजनिक API इंटरफ़ेस का सारांश प्रस्तुत करता है: मुख्य प्रकार, `Detector` इंटरफ़ेस, `Engine` रजिस्ट्री, स्टोरेज बैकएंड इंटरफ़ेस और HTTP वैलिडेटर कंस्ट्रक्टर।

## मुख्य प्रकार

### Result

डिटेक्शन परिणाम स्ट्रक्चर, जिसे प्रत्येक डिटेक्टर लौटाता है:

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

गंभीरता स्तर:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector इंटरफ़ेस

सभी डिटेक्टर को यह इंटरफ़ेस लागू करना आवश्यक है:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine रजिस्ट्री

`Engine` एकीकृत प्रवेश बिंदु है, जो डिटेक्टरों को नाम से पंजीकृत और प्रबंधित करता है:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` स्वतः अनुरोध के URL, Query, Headers, Cookies को इनपुट के रूप में एकत्रित करता है।

## पंजीकरण प्रवेश बिंदु

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## स्टोरेज बैकएंड इंटरफ़ेस

`httpval.IPBlacklist` इस इंटरफ़ेस के माध्यम से प्लगेबल स्टोरेज का उपयोग करता है:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

कार्यान्वयन:

| बैकएंड | विवरण |
|---------|--------|
| `storage.NewMemory()` | मेमोरी कार्यान्वयन, `sync.Mutex` + map, 30s में एक्सपायर्ड एंट्रीज़ की स्वतः सफाई |
| `storage.NewFile(path)` | JSON फ़ाइल पर्सिस्टेंस, 30s में स्वतः सेव + Close होने पर flush |
| `storage/redis` | Redis सबमॉड्यूल, Pipeline Incr + TTL, `go-redis/v9` आवश्यक |

## HTTP वैलिडेटर

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

## कस्टम डिटेक्टर उदाहरण

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
