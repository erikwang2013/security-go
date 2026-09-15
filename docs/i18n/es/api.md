# Security Go — Documentación de la API

Este documento resume todas las API públicas de `security-go`: tipos principales, interfaz `Detector`, registro `Engine`, interfaz del backend de almacenamiento y constructores de validadores HTTP.

## Tipos principales

### Result

Estructura de resultado de detección, devuelta por cada detector:

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

Niveles de severidad:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Interfaz Detector

Todos los detectores deben implementar esta interfaz:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Registro Engine

`Engine` es el punto de entrada unificado que registra y gestiona los detectores por nombre:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest` recopila automáticamente la URL, Query, Headers y Cookies de la petición como entrada.

## Punto de registro

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## Interfaz del backend de almacenamiento

`httpval.IPBlacklist` usa almacenamiento conectable a través de esta interfaz:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

Implementaciones:

| Backend | Descripción |
|------|------|
| `storage.NewMemory()` | Implementación en memoria, `sync.Mutex` + map, limpieza automática de entradas caducadas cada 30s |
| `storage.NewFile(path)` | Persistencia en archivos JSON, guardado automático cada 30s + flush en Close |
| `storage/redis` | Submódulo Redis, Pipeline Incr + TTL, requiere `go-redis/v9` |

## Validadores HTTP

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

### Profundidad de anidamiento JSON y atributos de cookie

| Constructor | Descripción |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Escanea en streaming un cuerpo JSON: informa `nested_depth` al superar la profundidad (por defecto 32) o el número de elementos. El JSON no válido o truncado nunca coincide |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Valida un `Set-Cookie`: atributos ausentes, valor demasiado largo (`MaxValueLen`), valor vacío (`RequireNonEmpty`) |

## Seguridad de sesión

El paquete `session` detecta el **secuestro del cliente**, la **manipulación de datos** y el **inicio de sesión desde otra ubicación**. Necesita el `*http.Request` completo (token, IP del cliente, User-Agent), así como el almacenamiento y la clave que aporta la aplicación, por lo que no se registra en la `Engine` y se invoca directamente como middleware/función.

### Interfaz Store

La vinculación de sesión no puede expresarse con `storage.Backend` (solo cuenta y bloqueo), por lo que `session` incluye una pequeña interfaz propia:

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

| Método | Descripción |
|------|------|
| `NewTracker(store) *Tracker` | Crea el tracker y rellena los valores por defecto |
| `Issue(token, r) error` | Tras un inicio de sesión correcto vincula token → subred IP / UA / huella; un token vacío devuelve error |
| `Check(r) *Result` | Valida en cada petición y devuelve `Detected: true` si hay coincidencia; si pasa, renueva de forma deslizante |
| `Observe(user, r) *Result` | Al iniciar sesión compara las subredes históricas de ese usuario y alerta cuando aparece una nueva subred; el primer inicio de sesión no tiene línea base y no alerta |
| `Guard(http.Handler) http.Handler` | Envoltorio de middleware: devuelve 401 si `Check` detecta |
| `Revoke(token) error` | Cierre de sesión: la sesión se invalida de inmediato |
| `DefaultTokenSource(r) string` | Toma `Authorization: Bearer <token>` y, en su defecto, la cookie `session` |
| `RecordFailure(token) error` | Cuenta un intento de autenticación fallido; al alcanzar `Failures` (por defecto 5 en 5 minutos) escribe un bloqueo, `Lockout` por defecto 15 minutos |
| `IsLocked(token) (bool, time.Time)` | Si el token está bloqueado y hasta cuándo; un error del almacén se lee como no bloqueado |
| `ClearFailures(token) error` | Pone a cero el contador de fallos tras un inicio de sesión correcto (el bloqueo corre con su propio temporizador) |

Valores de `Details["reason"]`:

| reason | Condición de activación | Nivel de severidad |
|--------|---------|---------|
| `missing_token` | La petición no lleva token | High |
| `unknown_token` | El token no fue emitido, ya se revocó con `Revoke` o ha caducado | High |
| `token_locked` | Umbral de fallos alcanzado dentro de la ventana, token bloqueado | Critical |
| `client_hijack` | Cambia el UA o cambia la huella del dispositivo | Critical |
| `remote_login` | `CountryOf` determina cambio de país (Critical) / IP en otra subred (High); lo comparten `Check` y `Observe` | Critical / High |
| `store_error` | Falla la lectura del almacenamiento y `FailClosed = true` | High |

> `TrustProxyHeaders` está desactivado por defecto: `X-Forwarded-For` / `X-Real-IP` son controlables por el cliente y, si se activa, un atacante puede falsificar la IP vinculada. Actívalo solo detrás de un proxy inverso propio.
> `FailClosed` está desactivado por defecto (se permite el paso cuando falla el almacenamiento), igual que en `httpval.IPBlacklist`. La clave de almacenamiento es el SHA-256 del token, por lo que una fuga del almacenamiento no entrega directamente un token utilizable.

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

Los parámetros se normalizan con `url.Values.Encode()` (ordenación + escapado), por lo que el orden del map no afecta al resultado. El orden de verificación es marca de tiempo → firma → contador de nonce, así que una firma falsificada no puede consumir un nonce legítimo; si `Nonces` es nil, solo se puede limitar la repetición mediante la ventana de marca de tiempo.

Valores de `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Ejemplo de detector personalizado

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
