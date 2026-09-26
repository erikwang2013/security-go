# Security Go — API ইন্টারফেস ডকুমেন্ট

এই ডকুমেন্টে `security-go`-এর সব পাবলিক API ইন্টারফেস সংক্ষিপ্ত করা হয়েছে: কোর টাইপ, `Detector` ইন্টারফেস, `Engine` রেজিস্ট্রি, স্টোরেজ ব্যাকএন্ড ইন্টারফেস ও HTTP ভ্যালিডেটর কনস্ট্রাক্টর।

## কোর টাইপ

### Result

ডিটেকশন ফলাফল স্ট্রাকচার, প্রতিটি ডিটেক্টর থেকে রিটার্ন হয়:

```go
type Result struct {
    Name     string                 // ডিটেক্টরের নাম
    Detected bool                   // আক্রমণ শনাক্ত হয়েছে কি না
    Message  string                 // ফলের বিবরণ
    Severity Severity               // তীব্রতা
    Details  map[string]interface{} // অতিরিক্ত বিবরণ
}
```

### Severity

তীব্রতার স্তর:

```go
type Severity int

const (
    SeverityLow      Severity = iota // কম ঝুঁকি
    SeverityMedium                   // মধ্যম ঝুঁকি
    SeverityHigh                     // উচ্চ ঝুঁকি
    SeverityCritical                 // সংকটপূর্ণ
)
```

## Detector ইন্টারফেস

সব ডিটেক্টরকে এই ইন্টারফেস বাস্তবায়ন করতে হবে:

```go
type Detector interface {
    Name() string                // ডিটেক্টরের অনন্য নাম
    Detect(input string) *Result // ইনপুটে শনাক্তকরণ চালায় ও ফল ফেরায়
}
```

## Engine রেজিস্ট্রি

`Engine` হলো ইউনিফাইড এন্ট্রি পয়েন্ট, যা নাম অনুযায়ী ডিটেক্টর নিবন্ধন ও পরিচালনা করে:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // খালি Engine তৈরি করে
func (e *Engine) Register(d Detector)             // একটি ডিটেক্টর নিবন্ধন করে
func (e *Engine) Detect(name, input string) *Result // নাম অনুযায়ী একটি ইনপুট শনাক্ত করে
func (e *Engine) DetectAll(input string) []*Result  // সম্পূর্ণ শনাক্তকরণ (শুধু Detected=true ফেরায়)
func (e *Engine) DetectRequest(r *http.Request) []*Result // সম্পূর্ণ HTTP রিকোয়েস্ট শনাক্ত করে
```

`DetectRequest` স্বয়ংক্রিয়ভাবে রিকোয়েস্টের URL, Query, Headers, Cookies সংগ্রহ করে ইনপুট হিসেবে ব্যবহার করে। প্রতিটি ইনপুট URL-ডিকোড করার পর আবার স্ক্যান করা হয়, তাই `%3Cscript%3E`-এর মতো এনকোডেড পেলোড এড়াতে পারে না।

## রেজিস্ট্রেশন এন্ট্রি পয়েন্ট

```go
// `all` প্যাকেজ এক কলে সব শূন্য-কনফিগ ডিটেক্টর নিবন্ধন করে (২৭টি)
all.RegisterAll(engine)
```

## সহায়ক ফাংশন

```go
// FirstMatch প্যারামিটার input-এর সাথে মেলে এমন প্রথম প্যাটার্নটি ফেরায়; কোনোটিই না মিললে ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

কাস্টম ডিটেক্টরগুলো যাতে বিল্ট-ইন প্রি-কম্পাইল করা প্যাটার্ন পুনরায় ব্যবহার করতে পারে, রেগুলার এক্সপ্রেশন আবার কম্পাইল না করে।

## স্টোরেজ ব্যাকএন্ড ইন্টারফেস

`httpval.IPBlacklist` এই ইন্টারফেসের মাধ্যমে প্লাগেবল স্টোরেজ ব্যবহার করে:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // উইন্ডোতে কাউন্ট +১
    Get(key string) (int, error)                          // কাউন্ট পড়ে
    Block(key string, duration time.Duration) error       // নির্দিষ্ট সময়ের জন্য ব্লক করে
    IsBlocked(key string) (bool, error)                   // ইতিমধ্যে ব্লক করা আছে কি না
    Close() error                                         // বন্ধ করে রিসোর্স মুক্ত করে
}
```

বাস্তবায়ন:

| ব্যাকএন্ড | বর্ণনা |
|-----------|--------|
| `storage.NewMemory() *Memory` | মেমোরি ইমপ্লিমেন্টেশন, `sync.Mutex` + map, 30s পর মেয়াদোত্তীর্ণ এন্ট্রি স্বয়ংক্রিয় পরিষ্কার |
| `storage.NewFile(path) (*File, error)` | JSON ফাইল পার্সিস্টেন্স, 30s পর স্বয়ংক্রিয় সেভ + Close করার সময় flush |
| `redis.New(addr, password string, db int) *Backend` | Redis সাবমডিউল, Pipeline Incr + TTL, `go-redis/v9` প্রয়োজন |

## HTTP ভ্যালিডেটর

```go
// HTTP মেথড হোয়াইটলিস্ট যাচাই
e.Register(&httpval.Method{})

// রিকোয়েস্ট বডির আকারসীমা (ডিফল্ট 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type হোয়াইটলিস্ট (খালি হোয়াইটলিস্ট = সব প্রত্যাখ্যান)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin যাচাই (ক্রস-অরিজিন রিকোয়েস্টে Origin ও Host মেলানো হয়)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP ব্ল্যাকলিস্ট (উইন্ডোতে Nটি আক্রমণের পর স্বয়ংক্রিয় ব্লক; ডিফল্ট 5টি/60s → ১৫ মিনিট ব্লক)
bl := httpval.NewIPBlacklist(mem) // mem যেকোনো storage.Backend বাস্তবায়ন
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
    Load(key string) ([]byte, error)   // না থাকলে বা মেয়াদোত্তীর্ণ হলে (nil, nil) ফেরায়
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // ইন-মেমরি বাস্তবায়ন, প্রতি 30 সেকেন্ডে মেয়াদোত্তীর্ণ এন্ট্রি পরিষ্কার করে, Close পরিষ্কার বন্ধ করে
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // সেশন তৈরির সময়ের ক্লায়েন্ট IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // ডিভাইস ফিঙ্গারপ্রিন্ট (X-Device-Fingerprint হেডার)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // প্রতিটি Check-এ স্লাইডিং নবায়ন
}
```

### Tracker

ডিটেক্টরের নাম `session_guard` (দেখুন `Tracker.Name()`)।

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // সেশনের আয়ুষ্কাল, ডিফল্ট 30m, প্রতিটি Check-এ স্লাইডিং নবায়ন
    SubnetBits        int                        // একই-স্থান নির্ণয়ের প্রিফিক্স, ডিফল্ট 24 (IPv6 স্বয়ংক্রিয়ভাবে +24)
    CountryOf         func(ip string) string     // ঐচ্ছিক GeoIP হুক; nil হলে দেশ যাচাই বাদ পড়ে
    KnownNets         int                        // Observe প্রতি ব্যবহারকারীর জন্য যতগুলো লগইন নেটওয়ার্ক রাখে, ডিফল্ট 8
    KnownNetTTL       time.Duration              // লগইন নেটওয়ার্ক সংরক্ষণের সময়, ডিফল্ট 90 দিন
    TokenSource       func(*http.Request) string // ডিফল্ট DefaultTokenSource
    TrustProxyHeaders bool                       // ডিফল্ট false
    FailClosed        bool                       // ডিফল্ট false
    Failures          int                        // উইন্ডোতে token লক করার ব্যর্থতার সীমা, ডিফল্ট 5
    FailureWindow     time.Duration              // ব্যর্থতার কাউন্ট সংরক্ষণের সময়, এর বেশি হলে গণনা হয় না, ডিফল্ট 5m
    Lockout           time.Duration              // প্রথমবার সীমায় পৌঁছালে ব্লকের সময়, প্রতিবার দ্বিগুণ হয়, ডিফল্ট 15m
    MaxLockout        time.Duration              // প্রতিবার ব্লক দ্বিগুণ হওয়ার ঊর্ধ্বসীমা, ডিফল্ট 24h
    BackoffWindow     time.Duration              // এস্কালেশন কাউন্টার সংরক্ষণের সময়, ডিফল্ট 24h
    StuffingLimit     int                        // একই IP যতগুলো ভিন্ন পরিচয়ের ক্ষেত্রে ব্যর্থ হতে পারে তার সীমা, ডিফল্ট 10
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

ডিটেক্টরের নাম `data_tamper` (দেখুন `Signer.Name()`)।

```go
type Signer struct {
    Secret  []byte           // শেয়ার করা HMAC কী, crypto/rand দিয়ে তৈরি
    MaxSkew time.Duration    // টাইমস্ট্যাম্পের অনুমোদিত বিচ্যুতি, ডিফল্ট 5m
    Nonces  storage.Backend  // ঐচ্ছিক: খালি না থাকলে উইন্ডো কাউন্টার দিয়ে স্বাক্ষরের রিপ্লে ঠেকানো হয় (ইনস্ট্যান্সজুড়ে, Redis পুনর্ব্যবহারযোগ্য)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // প্যারামিটার বদলেছে/কী মেলেনি/সময় শেষ/রিপ্লে
```

প্যারামিটার `url.Values.Encode()` দিয়ে ক্যানোনিকালাইজ করা হয় (সাজানো + এস্কেপ), map-এর ক্রম ফলাফলকে প্রভাবিত করে না। যাচাইয়ের ক্রম টাইমস্ট্যাম্প → সিগনেচার → nonce কাউন্টার, তাই জাল সিগনেচার বৈধ nonce খরচ করতে পারে না; `Nonces` nil হলে কেবল টাইমস্ট্যাম্প উইন্ডো দিয়ে রিপ্লে সীমিত করা যায়।

`Details["reason"]`-এর মান: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High)।

## ফাইল আপলোডের সহায়ক ফাংশন

ডিটেক্টর হিসেবে নিবন্ধনের পাশাপাশি আপলোড শনাক্তকরণ দুটি সরাসরি কলযোগ্য সহায়ক ফাংশনও দেয়:

```go
// HasMaliciousExt যাচাই করে ফাইলের এক্সটেনশনটি হোয়াইটলিস্টে (১৫টি) নেই কি না; এক্সটেনশন না থাকলে true
func HasMaliciousExt(filename string) bool

// CheckExtension একই সূত্র, তবে সম্পূর্ণ *Result ফেরায় (তীব্রতা ও বিবরণসহ)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

ফাইল ডিস্কে লেখার আগে দ্রুত প্রাথমিক যাচাইয়ের জন্য, `Engine` তৈরি না করেই।

## প্রকল্পের মাসকট

`pet` প্যাকেজ `go:embed`-এর মাধ্যমে কম্পাইল-সময়ে প্রকল্পের মাসকট Sentinel Gopher (哨兵鼠)-এর SVG এমবেড করে — কোনো তৃতীয়-পক্ষ নির্ভরতা নেই, রানটাইমে কোনো ফাইলও পড়া হয় না:

```go
func SVG() []byte         // কাঁচা SVG বাইট; স্লাইস শেয়ার করা, কলকারী এটি পরিবর্তন করবেন না
func Handler() http.Handler // image/svg+xml হিসেবে পরিবেশন করা হয়, এক দিনের Cache-Control
func Banner() string      // টার্মিনাল-বান্ধব প্লেইন টেক্সট ব্যানার, শেষে নিউলাইন সহ
```

```go
log.Println(pet.Banner())              // স্টার্টআপে প্রিন্ট করুন
http.Handle("/pet.svg", pet.Handler()) // ডিবাগ রুটে মাউন্ট করুন
```

`Handler` ভিতরে `http.ServeContent` ব্যবহার করে, তাই এতে `Content-Length` থাকে এবং `Range` ও `HEAD` সমর্থিত; সরাসরি `w.Write` করলে `net/http`-এর 2 KiB স্নিফ বাফার ছাড়িয়ে chunked রেসপন্সে পরিণত হয়।

## কাস্টম ডিটেক্টর উদাহরণ

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "ক্ষতিকর কনটেন্ট শনাক্ত",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
