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

`DetectRequest` स्वतः अनुरोध के URL, Query, Headers, Cookies को इनपुट के रूप में एकत्रित करता है। प्रत्येक इनपुट को URL-डिकोड करने के बाद दोबारा स्कैन किया जाता है, इसलिए `%3Cscript%3E` जैसे एन्कोडेड पेलोड बच नहीं सकते।

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

### JSON नेस्टिंग गहराई और कुकी एट्रिब्यूट

| कंस्ट्रक्टर | विवरण |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | JSON बॉडी को स्ट्रीम स्कैन करता है: नेस्टिंग गहराई (डिफ़ॉल्ट 32) या तत्व संख्या पार होने पर `nested_depth` रिपोर्ट करता है। अमान्य या कटा JSON कभी मेल नहीं खाता |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | एक `Set-Cookie` जाँचता है: अनुपस्थित एट्रिब्यूट, अत्यधिक लंबा मान (`MaxValueLen`), खाली मान (`RequireNonEmpty`) |

## सत्र सुरक्षा

`session` पैकेज **क्लाइंट हाईजैक**, **डेटा टैंपरिंग** और **रिमोट लॉगिन** का पता लगाता है। इसे पूरे `*http.Request` (token, क्लाइंट IP, User-Agent) के साथ-साथ एप्लिकेशन द्वारा दिए गए स्टोरेज और कुंजी की आवश्यकता होती है, इसलिए यह `Engine` में पंजीकृत नहीं होता और सीधे मिडलवेयर/फ़ंक्शन के रूप में कॉल किया जाता है।

### Store इंटरफ़ेस

सत्र बाइंडिंग को `storage.Backend` (जो केवल काउंटिंग और ब्लॉकिंग करता है) से व्यक्त नहीं किया जा सकता, इसलिए `session` अपना एक छोटा इंटरफ़ेस लाता है:

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

| विधि | विवरण |
|------|------|
| `NewTracker(store) *Tracker` | बनाता है और डिफ़ॉल्ट मान भरता है |
| `Issue(token, r) error` | लॉगिन सफल होने के बाद token → IP सबनेट / UA / फ़िंगरप्रिंट बाइंड करता है; खाली token पर त्रुटि लौटाता है |
| `Check(r) *Result` | प्रत्येक अनुरोध पर सत्यापन, मेल होने पर `Detected: true`; पास होने पर स्लाइडिंग नवीनीकरण |
| `Observe(user, r) *Result` | लॉगिन के समय उस उपयोगकर्ता के ऐतिहासिक लॉगिन सबनेट की तुलना, नया सबनेट दिखने पर चेतावनी; पहली बार लॉगिन पर बेसलाइन न होने से कोई चेतावनी नहीं |
| `Guard(http.Handler) http.Handler` | मिडलवेयर रैपर, `Check` मेल होते ही 401 लौटाता है |
| `Revoke(token) error` | लॉगआउट, सत्र तुरंत अमान्य हो जाता है |
| `DefaultTokenSource(r) string` | `Authorization: Bearer <token>` लेता है, अन्यथा `session` Cookie |
| `RecordFailure(token) error` | एक विफल प्रमाणीकरण गिनता है; विंडो में `Failures` (डिफ़ॉल्ट 5, 5 मिनट में) तक पहुँचने पर लॉक लिखा जाता है, `Lockout` डिफ़ॉल्ट 15 मिनट |
| `IsLocked(token) (bool, time.Time)` | टोकन लॉक है या नहीं और कब तक; स्टोर त्रुटि अनलॉक्ड मानी जाती है |
| `ClearFailures(token) error` | सफल लॉगिन पर विफलता गिनती शून्य करता है (लॉक अपने टाइमर पर चलता है) |

`Details["reason"]` के मान:

| reason | ट्रिगर शर्त | गंभीरता स्तर |
|--------|---------|---------|
| `missing_token` | अनुरोध में token नहीं है | High |
| `unknown_token` | token जारी नहीं हुआ, `Revoke` हो चुका या समाप्त | High |
| `token_locked` | सीमा पार होते ही विफलता गिनती, टोकन लॉक | Critical |
| `client_hijack` | UA बदलाव, या डिवाइस फ़िंगरप्रिंट बदलाव | Critical |
| `remote_login` | `CountryOf` से देश बदलाव (Critical) / IP सबनेट बदलाव (High), `Check` और `Observe` साझा | Critical / High |
| `store_error` | स्टोरेज पढ़ने में विफलता और `FailClosed = true` | High |

> `TrustProxyHeaders` डिफ़ॉल्ट रूप से बंद है: `X-Forwarded-For` / `X-Real-IP` क्लाइंट द्वारा नियंत्रित हो सकते हैं, चालू करने पर हाईजैकर बाइंड किए गए IP को नकली बना सकता है। इसे केवल अपने रिवर्स प्रॉक्सी के बाद ही चालू करें।
> `FailClosed` डिफ़ॉल्ट रूप से बंद है (स्टोरेज विफलता पर अनुमति), `httpval.IPBlacklist` के समान। स्टोरेज कुंजी token का SHA-256 है, स्टोरेज लीक होने पर सीधे उपयोग योग्य token नहीं मिलता।

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

पैरामीटर `url.Values.Encode()` से सामान्यीकृत होते हैं (क्रमबद्ध + एस्केप), map का क्रम परिणाम को प्रभावित नहीं करता। सत्यापन क्रम टाइमस्टैम्प → सिग्नेचर → nonce काउंटर है, इसलिए नकली सिग्नेचर वैध nonce को खर्च नहीं कर सकता; `Nonces` nil होने पर रीप्ले को केवल टाइमस्टैम्प विंडो सीमित करती है।

`Details["reason"]` के मान: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High)।

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
