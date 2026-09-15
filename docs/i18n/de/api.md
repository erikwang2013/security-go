# Security Go — API-Referenz

Dieses Dokument fasst alle öffentlichen APIs von `security-go` zusammen: Kerntypen, die `Detector`-Schnittstelle, die `Engine`-Registry, die Storage-Backend-Schnittstelle und die Konstruktoren der HTTP-Validator.

## Kerntypen

### Result

Die von jedem Detektor zurückgegebene Ergebnisstruktur:

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

Schweregrade:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector-Schnittstelle

Alle Detektoren müssen diese Schnittstelle implementieren:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine-Registry

`Engine` ist der zentrale Einstiegspunkt und verwaltet Detektoren, registriert nach Name:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` sammelt automatisch URL, Query, Headers und Cookies der Anfrage als Eingaben.

## Registrierungseinstieg

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## Storage-Backend-Schnittstelle

`httpval.IPBlacklist` nutzt über diese Schnittstelle steckbare Speicherung:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

Implementierungen:

| Backend | Beschreibung |
|---------|--------------|
| `storage.NewMemory()` | In-Memory-Implementierung, `sync.Mutex` + map, automatische Bereinigung abgelaufener Einträge nach 30 s |
| `storage.NewFile(path)` | JSON-Datei-Persistenz, automatisches Speichern alle 30 s + flush bei Close |
| `storage/redis` | Redis-Untermodul, Pipeline Incr + TTL, erfordert `go-redis/v9` |

## HTTP-Validator

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

### JSON-Verschachtelungstiefe und Cookie-Attribute

| Konstruktor | Beschreibung |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Streamt einen JSON-Body: meldet `nested_depth` bei Überschreitung der Tiefe (Standard 32) oder der Elementanzahl. Nicht-JSON und abgeschnittenes JSON treffen nie |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Prüft ein `Set-Cookie`: fehlende Attribute, überlanger Wert (`MaxValueLen`), leerer Wert (`RequireNonEmpty`) |

## Sitzungssicherheit

Das Paket `session` erkennt **Client-Entführung**, **Datenmanipulation** und **Anmeldung von einem anderen Ort**. Es benötigt den vollständigen `*http.Request` (Token, Client-IP, User-Agent) sowie den von der Anwendung bereitgestellten Speicher und Schlüssel; deshalb wird es nicht in die `Engine` registriert, sondern direkt als Middleware/Funktion aufgerufen.

### Store-Schnittstelle

Die Sitzungsbindung lässt sich nicht mit `storage.Backend` ausdrücken (nur Zähler und Sperren), daher bringt `session` eine eigene kleine Schnittstelle mit:

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

| Methode | Beschreibung |
|------|------|
| `NewTracker(store) *Tracker` | Erstellt den Tracker und füllt die Standardwerte ein |
| `Issue(token, r) error` | Bindet nach erfolgreicher Anmeldung token → IP-Subnetz / UA / Fingerabdruck; ein leeres token gibt einen Fehler zurück |
| `Check(r) *Result` | Prüft bei jeder Anfrage, liefert bei Treffer `Detected: true`; bei Erfolg gleitende Verlängerung |
| `Observe(user, r) *Result` | Vergleicht bei der Anmeldung die historischen Subnetze des Benutzers und warnt bei einem neuen Subnetz; die erste Anmeldung hat keine Basislinie und warnt nicht |
| `Guard(http.Handler) http.Handler` | Middleware-Wrapper, der bei Treffer von `Check` 401 zurückgibt |
| `Revoke(token) error` | Abmeldung, die Sitzung wird sofort ungültig |
| `DefaultTokenSource(r) string` | Liest `Authorization: Bearer <token>`, andernfalls das Cookie `session` |
| `RecordFailure(token) error` | Zählt eine fehlgeschlagene Anmeldung; bei Erreichen von `Failures` (Standard 5 in 5 Minuten) wird eine Sperre geschrieben, `Lockout` Standard 15 Minuten |
| `IsLocked(token) (bool, time.Time)` | Ob das Token gesperrt ist und bis wann; ein Speicherfehler gilt als nicht gesperrt |
| `ClearFailures(token) error` | Setzt den Fehlerzähler nach erfolgreicher Anmeldung zurück (eine Sperre läuft über ihren eigenen Timer) |

Werte von `Details["reason"]`:

| reason | Auslösebedingung | Schweregrad |
|--------|---------|---------|
| `missing_token` | Die Anfrage enthält kein token | High |
| `unknown_token` | token wurde nicht ausgestellt, wurde per `Revoke` beendet oder ist abgelaufen | High |
| `token_locked` | Fehlerschwelle im Fenster erreicht, Token gesperrt | Critical |
| `client_hijack` | UA geändert oder Gerätefingerabdruck geändert | Critical |
| `remote_login` | `CountryOf` stellt einen Länderwechsel fest (Critical) / IP in einem anderen Subnetz (High); wird von `Check` und `Observe` gemeinsam genutzt | Critical / High |
| `store_error` | Speicherlesefehler und `FailClosed = true` | High |

> `TrustProxyHeaders` ist standardmäßig deaktiviert: `X-Forwarded-For` / `X-Real-IP` sind vom Client kontrollierbar; nach dem Aktivieren kann ein Angreifer die gebundene IP fälschen. Nur hinter einem eigenen Reverse-Proxy aktivieren.
> `FailClosed` ist standardmäßig deaktiviert (Freigabe bei Speicherfehlern), konsistent mit `httpval.IPBlacklist`. Der Speicherschlüssel ist der SHA-256 des token; ein Speicherleck liefert daher keinen direkt nutzbaren token.

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

Parameter werden über `url.Values.Encode()` normalisiert (Sortierung + Escaping), die Map-Reihenfolge beeinflusst das Ergebnis nicht. Die Prüfreihenfolge ist Zeitstempel → Signatur → Nonce-Zähler, daher kann eine gefälschte Signatur keine gültige Nonce verbrauchen; ist `Nonces` nil, lässt sich Replay nur über das Zeitstempel-Fenster einschränken.

Werte von `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Beispiel für benutzerdefinierte Detektoren

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
