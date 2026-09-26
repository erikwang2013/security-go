# Security Go — API दस्तावेज़

यह दस्तावेज़ `security-go` के सभी सार्वजनिक API इंटरफ़ेस का सारांश प्रस्तुत करता है: मुख्य प्रकार, `Detector` इंटरफ़ेस, `Engine` रजिस्ट्री, स्टोरेज बैकएंड इंटरफ़ेस और HTTP वैलिडेटर कंस्ट्रक्टर।

## मुख्य प्रकार

### Result

डिटेक्शन परिणाम स्ट्रक्चर, जिसे प्रत्येक डिटेक्टर लौटाता है:

```go
type Result struct {
    Name     string                 // डिटेक्टर का नाम
    Detected bool                   // क्या हमला पाया गया
    Message  string                 // परिणाम विवरण
    Severity Severity               // गंभीरता स्तर
    Details  map[string]interface{} // अतिरिक्त विवरण
}
```

### Severity

गंभीरता स्तर:

```go
type Severity int

const (
    SeverityLow      Severity = iota // कम जोखिम
    SeverityMedium                   // मध्यम जोखिम
    SeverityHigh                     // उच्च जोखिम
    SeverityCritical                 // गंभीर
)
```

## Detector इंटरफ़ेस

सभी डिटेक्टर को यह इंटरफ़ेस लागू करना आवश्यक है:

```go
type Detector interface {
    Name() string                // डिटेक्टर का अनूठा नाम
    Detect(input string) *Result // इनपुट पर डिटेक्शन चलाएँ, परिणाम लौटाएँ
}
```

## Engine रजिस्ट्री

`Engine` एकीकृत प्रवेश बिंदु है, जो डिटेक्टरों को नाम से पंजीकृत और प्रबंधित करता है:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // खाली Engine बनाता है
func (e *Engine) Register(d Detector)             // डिटेक्टर पंजीकृत करता है
func (e *Engine) Detect(name, input string) *Result // नाम से एक इनपुट की जाँच
func (e *Engine) DetectAll(input string) []*Result  // पूर्ण जाँच (केवल Detected=true लौटाता है)
func (e *Engine) DetectRequest(r *http.Request) []*Result // पूरा HTTP अनुरोध जाँचता है
```

`DetectRequest` स्वतः अनुरोध के URL, Query, Headers, Cookies को इनपुट के रूप में एकत्रित करता है। प्रत्येक इनपुट को URL-डिकोड करने के बाद दोबारा स्कैन किया जाता है, इसलिए `%3Cscript%3E` जैसे एन्कोडेड पेलोड बच नहीं सकते।

## पंजीकरण प्रवेश बिंदु

```go
// all पैकेज सभी शून्य-कॉन्फ़िग डिटेक्टरों को एक बार में पंजीकृत करता है (27)
all.RegisterAll(engine)
```

## सहायक फ़ंक्शन

```go
// FirstMatch input से मेल खाने वाला पहला पैटर्न स्ट्रिंग लौटाता है; कोई मेल न हो तो ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

कस्टम डिटेक्टरों के लिए अंतर्निहित पूर्व-संकलित पैटर्न का पुनः उपयोग करें, रेगुलर एक्सप्रेशन दोबारा संकलित करने से बचें।

## स्टोरेज बैकएंड इंटरफ़ेस

`httpval.IPBlacklist` इस इंटरफ़ेस के माध्यम से प्लगेबल स्टोरेज का उपयोग करता है:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // विंडो में गिनती +1
    Get(key string) (int, error)                          // गिनती पढ़ता है
    Block(key string, duration time.Duration) error       // निर्दिष्ट अवधि के लिए ब्लॉक
    IsBlocked(key string) (bool, error)                   // क्या पहले से ब्लॉक है
    Close() error                                         // बंद करता है और संसाधन मुक्त करता है
}
```

कार्यान्वयन:

| बैकएंड | विवरण |
|---------|--------|
| `storage.NewMemory() *Memory` | मेमोरी कार्यान्वयन, `sync.Mutex` + map, 30s में एक्सपायर्ड एंट्रीज़ की स्वतः सफाई |
| `storage.NewFile(path) (*File, error)` | JSON फ़ाइल पर्सिस्टेंस, 30s में स्वतः सेव + Close होने पर flush |
| `redis.New(addr, password string, db int) *Backend` | Redis सबमॉड्यूल, Pipeline Incr + TTL, `go-redis/v9` आवश्यक |

## HTTP वैलिडेटर

```go
// HTTP विधि व्हाइटलिस्ट सत्यापन
e.Register(&httpval.Method{})

// अनुरोध बॉडी आकार सीमा (डिफ़ॉल्ट 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type व्हाइटलिस्ट (खाली सूची = सभी अस्वीकार)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin सत्यापन (क्रॉस-ओरिजिन अनुरोध में Origin और Host का मिलान)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP ब्लैकलिस्ट (विंडो में N हमलों पर स्वतः ब्लॉक, डिफ़ॉल्ट 5/60s → 15 मिनट ब्लॉक)
bl := httpval.NewIPBlacklist(mem) // mem कोई भी storage.Backend कार्यान्वयन है
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
    Load(key string) ([]byte, error)   // अनुपस्थित या समाप्त होने पर (nil, nil) लौटाता है
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // मेमोरी कार्यान्वयन, 30s में एक्सपायर्ड एंट्रीज़ की सफाई, Close पर सफाई बंद
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // सत्र स्थापित करते समय क्लाइंट IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // डिवाइस फ़िंगरप्रिंट (X-Device-Fingerprint हेडर)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // प्रत्येक Check पर स्लाइडिंग नवीनीकरण
}
```

### Tracker

डिटेक्टर का नाम `session_guard` (देखें `Tracker.Name()`)।

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // सत्र जीवनकाल, डिफ़ॉल्ट 30m, प्रत्येक Check पर स्लाइडिंग नवीनीकरण
    SubnetBits        int                        // समान-स्थान निर्धारण प्रीफ़िक्स, डिफ़ॉल्ट 24 (IPv6 में स्वतः +24)
    CountryOf         func(ip string) string     // वैकल्पिक GeoIP हुक; nil होने पर देश जाँच छोड़ें
    KnownNets         int                        // Observe प्रति उपयोगकर्ता रखे जाने वाले लॉगिन सबनेट, डिफ़ॉल्ट 8
    KnownNetTTL       time.Duration              // लॉगिन सबनेट प्रतिधारण अवधि, डिफ़ॉल्ट 90 दिन
    TokenSource       func(*http.Request) string // डिफ़ॉल्ट DefaultTokenSource
    TrustProxyHeaders bool                       // डिफ़ॉल्ट false
    FailClosed        bool                       // डिफ़ॉल्ट false
    Failures          int                        // विंडो में token लॉक करने वाली विफलताओं की सीमा, डिफ़ॉल्ट 5
    FailureWindow     time.Duration              // विफलता गिनती प्रतिधारण अवधि, अधिक होने पर नहीं गिना जाता, डिफ़ॉल्ट 5m
    Lockout           time.Duration              // सीमा पर पहुँचने पर पहला लॉक, हर बार दोगुना, डिफ़ॉल्ट 15m
    MaxLockout        time.Duration              // प्रत्येक लॉक दोगुना होने की ऊपरी सीमा, डिफ़ॉल्ट 24h
    BackoffWindow     time.Duration              // एस्केलेशन गिनती की प्रतिधारण अवधि, डिफ़ॉल्ट 24h
    StuffingLimit     int                        // एक ही IP पर विफल विभिन्न पहचानों की सीमा, डिफ़ॉल्ट 10
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
| `RecordFailure(identity, r) error` | एक विफल लॉगिन गिनता है (identity प्रमाणीकरण कुंजी है जैसे उपयोगकर्ता नाम, r क्लाइंट IP देता है)। विंडो में `Failures` (डिफ़ॉल्ट 5, 5 मिनट में) तक पहुँचने पर पहचान लॉक होती है, हर बार दोगुनी होकर `MaxLockout` (डिफ़ॉल्ट 24 घंटे) तक |
| `CheckLogin(identity, r) *Result` | लॉगिन प्रयास की पूर्व-जाँच: पहचान लॉक हो तो `token_locked`, क्लाइंट IP पहले ही `StuffingLimit` (डिफ़ॉल्ट 10) भिन्न पहचानों पर विफल हो तो `credential_stuffing` — दोनों Critical |
| `GuardLogin(next, identity) http.Handler` | प्रमाणीकरण एंडपॉइंट के लिए मिडलवेयर: मेल खाने पर `Retry-After` सहित 429; बाद में 401 विफलता गिना जाता है और 2xx गिनती शून्य करता है |
| `IsLocked(token) (bool, time.Time)` | टोकन लॉक है या नहीं और कब तक; स्टोर त्रुटि अनलॉक्ड मानी जाती है |
| `ClearFailures(token) error` | सफल लॉगिन पर विफलता गिनती शून्य करता है (लॉक अपने टाइमर पर चलता है) |

`Details["reason"]` के मान:

| reason | ट्रिगर शर्त | गंभीरता स्तर |
|--------|---------|---------|
| `missing_token` | अनुरोध में token नहीं है | High |
| `unknown_token` | token जारी नहीं हुआ, `Revoke` हो चुका या समाप्त | High |
| `token_locked` | सीमा पार होते ही विफलता गिनती, टोकन लॉक | Critical |
| `credential_stuffing` | एक IP विंडो में `StuffingLimit` भिन्न पहचानों पर विफल | Critical |
| `client_hijack` | UA बदलाव, या डिवाइस फ़िंगरप्रिंट बदलाव | Critical |
| `remote_login` | `CountryOf` से देश बदलाव (Critical) / IP सबनेट बदलाव (High), `Check` और `Observe` साझा | Critical / High |
| `store_error` | स्टोरेज पढ़ने में विफलता और `FailClosed = true` | High |

> `TrustProxyHeaders` डिफ़ॉल्ट रूप से बंद है: `X-Forwarded-For` / `X-Real-IP` क्लाइंट द्वारा नियंत्रित हो सकते हैं, चालू करने पर हाईजैकर बाइंड किए गए IP को नकली बना सकता है। इसे केवल अपने रिवर्स प्रॉक्सी के बाद ही चालू करें।
> `FailClosed` डिफ़ॉल्ट रूप से बंद है (स्टोरेज विफलता पर अनुमति), `httpval.IPBlacklist` के समान। स्टोरेज कुंजी token का SHA-256 है, स्टोरेज लीक होने पर सीधे उपयोग योग्य token नहीं मिलता।

### Signer

डिटेक्टर का नाम `data_tamper` (देखें `Signer.Name()`)।

```go
type Signer struct {
    Secret  []byte           // साझा HMAC कुंजी, crypto/rand से बनाएँ
    MaxSkew time.Duration    // अनुमत टाइमस्टैम्प अंतर, डिफ़ॉल्ट 5m
    Nonces  storage.Backend  // वैकल्पिक: गैर-nil होने पर विंडो गिनती से हस्ताक्षर रीप्ले रोकें (क्रॉस-इंस्टेंस संभव, Redis का पुनः उपयोग)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // पैरामीटर बदले/कुंजी मेल नहीं/समय समाप्त/रीप्ले
```

पैरामीटर `url.Values.Encode()` से सामान्यीकृत होते हैं (क्रमबद्ध + एस्केप), map का क्रम परिणाम को प्रभावित नहीं करता। सत्यापन क्रम टाइमस्टैम्प → सिग्नेचर → nonce काउंटर है, इसलिए नकली सिग्नेचर वैध nonce को खर्च नहीं कर सकता; `Nonces` nil होने पर रीप्ले को केवल टाइमस्टैम्प विंडो सीमित करती है।

`Details["reason"]` के मान: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High)।

## फ़ाइल अपलोड सहायक फ़ंक्शन

अपलोड डिटेक्शन डिटेक्टर के रूप में पंजीकरण के अलावा दो सीधे कॉल करने योग्य सहायक फ़ंक्शन भी निर्यात करता है:

```go
// HasMaliciousExt बताता है कि फ़ाइल नाम का एक्सटेंशन व्हाइटलिस्ट (15 प्रकार) में नहीं है; एक्सटेंशन न हो तो true
func HasMaliciousExt(filename string) bool

// CheckExtension ऊपर के समान स्रोत से है, पर पूरा *Result लौटाता है (गंभीरता और विवरण सहित)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

फ़ाइल डिस्क पर लिखे जाने से पहले त्वरित पूर्व-जाँच के लिए, `Engine` बनाने की आवश्यकता नहीं।

## प्रोजेक्ट शुभंकर

`pet` पैकेज कंपाइल समय पर `go:embed` के ज़रिए प्रोजेक्ट शुभंकर Sentinel Gopher का SVG एम्बेड करता है — कोई तीसरे पक्ष की निर्भरता नहीं, रनटाइम पर कोई फ़ाइल नहीं पढ़ी जाती:

```go
func SVG() []byte         // कच्चे SVG बाइट्स; स्लाइस साझा है, कॉलर को बदलना नहीं चाहिए
func Handler() http.Handler // image/svg+xml के रूप में परोसा जाता है, Cache-Control एक दिन
func Banner() string      // टर्मिनल के अनुकूल सादा टेक्स्ट बैनर, अंत में न्यूलाइन
```

```go
log.Println(pet.Banner())              // स्टार्टअप पर प्रिंट करें
http.Handle("/pet.svg", pet.Handler()) // डिबग रूट पर माउंट करें
```

`Handler` भीतर से `http.ServeContent` का उपयोग करता है, इसलिए `Content-Length` के साथ आता है और `Range` व `HEAD` का समर्थन करता है; सीधा `w.Write` `net/http` के 2 KiB स्निफ़ बफ़र से अधिक होकर chunked प्रतिक्रिया में बदल जाता है।

### मुद्रा: डिटेक्शन परिणामों से संचालित

मास्कोट स्थिर चित्र नहीं है — इसकी ढाल, रडार और आवर्धक लेंस स्कैन परिणाम के अनुसार रंग बदलते हैं, और सीधे खतरे के स्तर के संकेतक का काम करते हैं:

```go
type Mood int

const (
    Calm     Mood = iota // स्कैन में कोई हिट नहीं
    Watchful             // हिट हैं, पर कोई High / Critical नहीं
    Alarmed              // कम से कम एक High या Critical, संभालना आवश्यक
)

func MoodOf(results []*security.Result) Mood  // सबसे गंभीर हिट से स्तर तय
func SVGFor(m Mood) []byte                    // उस मुद्रा का चित्र; अज्ञात मान पर Calm पर वापस
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler
```

`MoodOf` केवल उन परिणामों को गिनता है जिनमें `Detected` सही है — डिटेक्टर बिना हिट के भी `Severity` रखता है, इसलिए केवल गंभीरता से अलार्म नहीं बजना चाहिए। जो हिट जितनी गंभीर है उसकी प्राथमिकता उतनी ऊँची, परिणामों के क्रम से स्वतंत्र।

इंजन जोड़िए, और यह एक जीवंत खतरा-स्थिति चित्र बन जाता है:

```go
e := security.NewEngine()
all.RegisterAll(e)

http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` में `Cache-Control: no-store` रहता है — स्थिर `Handler` से अलग, इसका आउटपुट स्कैन परिणाम के साथ बदलता है; एक दिन का कैश पुरानी स्थिति लौटाएगा।

## कस्टम डिटेक्टर उदाहरण

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "दुर्भावनापूर्ण सामग्री पाई गई",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
