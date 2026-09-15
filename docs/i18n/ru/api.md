# Security Go — Документация API

В этом документе собраны все публичные API-интерфейсы `security-go`: основные типы, интерфейс `Detector`, реестр `Engine`, интерфейс бэкенда хранилища и конструкторы HTTP-валидаторов.

## Основные типы

### Result

Структура результата обнаружения, возвращаемая каждым детектором:

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

Уровни серьёзности:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Интерфейс Detector

Все детекторы обязаны реализовывать этот интерфейс:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Реестр Engine

`Engine` — единая точка входа, регистрирует и управляет детекторами по имени:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` автоматически собирает URL, Query, Headers и Cookies запроса в качестве входных данных. Каждый вход дополнительно проверяется после URL-декодирования, поэтому закодированные полезные нагрузки вроде `%3Cscript%3E` не обходят обнаружение.

## Точка регистрации

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## Интерфейс бэкенда хранилища

`httpval.IPBlacklist` использует подключаемое хранилище через этот интерфейс:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

Реализации:

| Бэкенд | Описание |
|------|------|
| `storage.NewMemory()` | реализация в памяти, `sync.Mutex` + map, автоматическая очистка устаревших записей каждые 30 с |
| `storage.NewFile(path)` | JSON-персистентность на диск, автосохранение каждые 30 с + flush при Close |
| `storage/redis` | подмодуль Redis, Pipeline Incr + TTL, требуется `go-redis/v9` |

## HTTP-валидаторы

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

### Глубина вложенности JSON и атрибуты cookie

| Конструктор | Описание |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Потоково разбирает тело JSON: сообщает `nested_depth` при превышении глубины (по умолчанию 32) или числа элементов. Некорректный и обрезанный JSON не совпадает никогда |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Проверяет один `Set-Cookie`: отсутствующие атрибуты, слишком длинное значение (`MaxValueLen`), пустое значение (`RequireNonEmpty`) |

## Безопасность сессий

Пакет `session` обнаруживает **перехват клиента**, **подмену данных** и **удалённый вход**. Ему требуется полный `*http.Request` (token, IP-адрес клиента, User-Agent), а также хранилище и ключ, предоставляемые приложением, поэтому он не регистрируется в `Engine`, а вызывается напрямую как мидлвар/функция.

### Интерфейс Store

Привязку сессии нельзя выразить через `storage.Backend` (в нём есть только счётчики и блокировки), поэтому `session` содержит небольшой собственный интерфейс:

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

| Метод | Описание |
|------|------|
| `NewTracker(store) *Tracker` | создаёт трекер и заполняет значения по умолчанию |
| `Issue(token, r) error` | после успешного входа привязывает token → подсеть IP / UA / отпечаток; пустой token возвращает ошибку |
| `Check(r) *Result` | проверка при каждом запросе; при срабатывании возвращает `Detected: true`, при прохождении продлевает сессию скользящим образом |
| `Observe(user, r) *Result` | при входе сравнивает исторические подсети этого пользователя, предупреждает при появлении новой; при первом входе без базовой линии предупреждения нет |
| `Guard(http.Handler) http.Handler` | обёртка-мидлвар: при срабатывании `Check` возвращает 401 |
| `Revoke(token) error` | выход из системы, сессия аннулируется немедленно |
| `DefaultTokenSource(r) string` | берёт `Authorization: Bearer <token>`, затем Cookie `session` |
| `RecordFailure(identity, r) error` | Считает один неудачный вход (identity — ключ аутентификации, например имя пользователя; r даёт IP клиента). При достижении `Failures` (по умолчанию 5 за 5 минут) идентификатор блокируется, каждая блокировка удваивается до `MaxLockout` (по умолчанию 24 ч) |
| `CheckLogin(identity, r) *Result` | Предварительная проверка попытки входа: `token_locked` при заблокированном идентификаторе, `credential_stuffing` если IP уже провалился против `StuffingLimit` (по умолчанию 10) разных идентификаторов — оба Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware для точки аутентификации: 429 с `Retry-After` при срабатывании; после обработчика 401 считается неудачей, а 2xx сбрасывает счётчик |
| `IsLocked(token) (bool, time.Time)` | Заблокирован ли токен и до какого времени; ошибка хранилища читается как «не заблокирован» |
| `ClearFailures(token) error` | Сбрасывает счётчик неудач после успешного входа (блокировка идёт по своему таймеру) |

`Details["reason"]` принимает значения:

| reason | Условие срабатывания | Уровень серьёзности |
|--------|---------|---------|
| `missing_token` | запрос не содержит token | High |
| `unknown_token` | token не выдан, отозван через `Revoke` или истёк | High |
| `token_locked` | Порог неудач достигнут внутри окна, токен заблокирован | Critical |
| `credential_stuffing` | Один IP провалился против `StuffingLimit` разных идентификаторов внутри окна | Critical |
| `client_hijack` | изменение UA или отпечатка устройства | Critical |
| `remote_login` | `CountryOf` определяет смену страны (Critical) / IP выходит за пределы подсети (High); общий для `Check` и `Observe` | Critical / High |
| `store_error` | ошибка чтения хранилища при `FailClosed = true` | High |

> `TrustProxyHeaders` по умолчанию отключён: `X-Forwarded-For` / `X-Real-IP` контролируются клиентом, при включении перехватчик сможет подделать привязанный IP. Включайте только за собственным обратным прокси.
> `FailClosed` по умолчанию отключён (при сбое хранилища запрос пропускается), как и в `httpval.IPBlacklist`. Ключ хранилища — SHA-256 от token, поэтому утечка хранилища не даёт напрямую рабочий token.

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

Параметры нормализуются через `url.Values.Encode()` (сортировка + экранирование), порядок ключей в map не влияет на результат. Порядок проверки — временная метка → подпись → счётчик nonce, поэтому подделанная подпись не может израсходовать легитимный nonce; при `Nonces` = nil воспроизведение ограничивается только окном временной метки.

`Details["reason"]` принимает значения: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Пример собственного детектора

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
