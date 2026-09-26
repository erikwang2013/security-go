# Security Go — Documentación de la API

Este documento resume todas las API públicas de `security-go`: tipos principales, interfaz `Detector`, registro `Engine`, interfaz del backend de almacenamiento y constructores de validadores HTTP.

## Tipos principales

### Result

Estructura de resultado de detección, devuelta por cada detector:

```go
type Result struct {
    Name     string                 // Nombre del detector
    Detected bool                   // si se detectó un ataque
    Message  string                 // Descripción del resultado
    Severity Severity               // Gravedad
    Details  map[string]interface{} // Detalles adicionales
}
```

### Severity

Niveles de severidad:

```go
type Severity int

const (
    SeverityLow      Severity = iota // riesgo bajo
    SeverityMedium                   // riesgo medio
    SeverityHigh                     // riesgo alto
    SeverityCritical                 // crítico
)
```

## Interfaz Detector

Todos los detectores deben implementar esta interfaz:

```go
type Detector interface {
    Name() string                // nombre único del detector
    Detect(input string) *Result // ejecuta la detección sobre la entrada y devuelve el resultado
}
```

## Registro Engine

`Engine` es el punto de entrada unificado que registra y gestiona los detectores por nombre:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // crea una Engine vacía
func (e *Engine) Register(d Detector)             // registra un detector
func (e *Engine) Detect(name, input string) *Result // detecta una sola entrada por nombre
func (e *Engine) DetectAll(input string) []*Result  // detecta todo (solo devuelve Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // detecta una petición HTTP completa
```

`DetectRequest` recopila automáticamente la URL, Query, Headers y Cookies de la petición como entrada. Cada entrada se vuelve a escanear tras decodificarla de URL, de modo que cargas codificadas como `%3Cscript%3E` no pueden eludir la detección.

## Punto de registro

```go
// El paquete all registra con una sola llamada todos los detectores sin configuración (27)
all.RegisterAll(engine)
```

## Funciones auxiliares

```go
// FirstMatch devuelve el primer patrón que coincide con input; si no coincide ninguno ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Permite que los detectores personalizados reutilicen los patrones precompilados integrados y eviten recompilar expresiones regulares.

## Interfaz del backend de almacenamiento

`httpval.IPBlacklist` usa almacenamiento conectable a través de esta interfaz:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // contador dentro de la ventana +1
    Get(key string) (int, error)                          // lee el contador
    Block(key string, duration time.Duration) error       // bloquea durante la duración indicada
    IsBlocked(key string) (bool, error)                   // si ya está bloqueado
    Close() error                                         // cierra y libera recursos
}
```

Implementaciones:

| Backend | Descripción |
|------|------|
| `storage.NewMemory() *Memory` | Implementación en memoria, `sync.Mutex` + map, limpieza automática de entradas caducadas cada 30s |
| `storage.NewFile(path) (*File, error)` | Persistencia en archivos JSON, guardado automático cada 30s + flush en Close |
| `redis.New(addr, password string, db int) *Backend` | Submódulo Redis, Pipeline Incr + TTL, requiere `go-redis/v9` |

## Validadores HTTP

```go
// validación de la lista blanca de métodos HTTP
e.Register(&httpval.Method{})

// límite del tamaño del cuerpo de la petición (10 MB por defecto)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// lista blanca de Content-Type (lista vacía = rechazar todo)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// validación de Origin para CSRF (en peticiones cross-origin se comprueba que Origin coincida con Host)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// lista negra de IP (bloqueo automático tras N ataques en la ventana; por defecto 5/60 s → 15 minutos de bloqueo)
bl := httpval.NewIPBlacklist(mem) // mem es cualquier implementación de storage.Backend
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
    Load(key string) ([]byte, error)   // devuelve (nil, nil) si no existe o ha caducado
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // implementación en memoria, limpia las entradas caducadas cada 30 s y Close detiene la limpieza
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // IP del cliente al crear la sesión
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // huella del dispositivo (cabecera X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // renovación deslizante en cada Check
}
```

### Tracker

Nombre del detector `session_guard` (véase `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // duración de la sesión, 30m por defecto, renovación deslizante en cada Check
    SubnetBits        int                        // prefijo para determinar la misma ubicación, 24 por defecto (IPv6 +24 automáticamente)
    CountryOf         func(ip string) string     // hook GeoIP opcional; si es nil se omite la comprobación de país
    KnownNets         int                        // número de redes de inicio de sesión que Observe conserva por usuario, 8 por defecto
    KnownNetTTL       time.Duration              // tiempo de conservación de las redes de inicio de sesión, 90 días por defecto
    TokenSource       func(*http.Request) string // DefaultTokenSource por defecto
    TrustProxyHeaders bool                       // false por defecto
    FailClosed        bool                       // false por defecto
    Failures          int                        // umbral de fallos en la ventana para bloquear el token, 5 por defecto
    FailureWindow     time.Duration              // tiempo de conservación del contador de fallos, lo que lo supera no cuenta, 5m por defecto
    Lockout           time.Duration              // duración del bloqueo al alcanzar el umbral por primera vez, se duplica cada vez, 15m por defecto
    MaxLockout        time.Duration              // límite superior de la duplicación en cada bloqueo, 24h por defecto
    BackoffWindow     time.Duration              // tiempo de conservación del contador de escalado, 24h por defecto
    StuffingLimit     int                        // número máximo de identidades distintas que una misma IP puede fallar, 10 por defecto
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
| `RecordFailure(identity, r) error` | Cuenta un inicio de sesión fallido (identity es la clave de autenticación, como el usuario; r aporta la IP del cliente). Al alcanzar `Failures` (por defecto 5 en 5 minutos) bloquea la identidad, duplicándose cada vez hasta `MaxLockout` (por defecto 24 h) |
| `CheckLogin(identity, r) *Result` | Comprobación previa del intento: `token_locked` si la identidad está bloqueada, `credential_stuffing` si la IP ya falló contra `StuffingLimit` (por defecto 10) identidades distintas — ambos Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware para el endpoint de autenticación: 429 con `Retry-After` al dispararse; después del handler un 401 cuenta como fallo y un 2xx pone el contador a cero |
| `IsLocked(token) (bool, time.Time)` | Si el token está bloqueado y hasta cuándo; un error del almacén se lee como no bloqueado |
| `ClearFailures(token) error` | Pone a cero el contador de fallos tras un inicio de sesión correcto (el bloqueo corre con su propio temporizador) |

Valores de `Details["reason"]`:

| reason | Condición de activación | Nivel de severidad |
|--------|---------|---------|
| `missing_token` | La petición no lleva token | High |
| `unknown_token` | El token no fue emitido, ya se revocó con `Revoke` o ha caducado | High |
| `token_locked` | Umbral de fallos alcanzado dentro de la ventana, token bloqueado | Critical |
| `credential_stuffing` | Una IP falló contra `StuffingLimit` identidades distintas dentro de la ventana | Critical |
| `client_hijack` | Cambia el UA o cambia la huella del dispositivo | Critical |
| `remote_login` | `CountryOf` determina cambio de país (Critical) / IP en otra subred (High); lo comparten `Check` y `Observe` | Critical / High |
| `store_error` | Falla la lectura del almacenamiento y `FailClosed = true` | High |

> `TrustProxyHeaders` está desactivado por defecto: `X-Forwarded-For` / `X-Real-IP` son controlables por el cliente y, si se activa, un atacante puede falsificar la IP vinculada. Actívalo solo detrás de un proxy inverso propio.
> `FailClosed` está desactivado por defecto (se permite el paso cuando falla el almacenamiento), igual que en `httpval.IPBlacklist`. La clave de almacenamiento es el SHA-256 del token, por lo que una fuga del almacenamiento no entrega directamente un token utilizable.

### Signer

Nombre del detector `data_tamper` (véase `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // clave HMAC compartida, generada con crypto/rand
    MaxSkew time.Duration    // desviación permitida del timestamp, 5m por defecto
    Nonces  storage.Backend  // opcional: si no está vacío, un contador de ventana bloquea la repetición de firmas (entre instancias, reutilizando Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // parámetros alterados/clave incorrecta/caducado/repetido
```

Los parámetros se normalizan con `url.Values.Encode()` (ordenación + escapado), por lo que el orden del map no afecta al resultado. El orden de verificación es marca de tiempo → firma → contador de nonce, así que una firma falsificada no puede consumir un nonce legítimo; si `Nonces` es nil, solo se puede limitar la repetición mediante la ventana de marca de tiempo.

Valores de `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Funciones auxiliares para la subida de archivos

Además de registrarse como detector, la detección de subidas exporta dos funciones auxiliares que se pueden llamar directamente:

```go
// HasMaliciousExt indica si la extensión del nombre no está en la lista blanca (15 extensiones); sin extensión devuelve true
func HasMaliciousExt(filename string) bool

// CheckExtension comparte el mismo origen, pero devuelve un *Result completo (con gravedad y descripción)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Sirven para hacer una comprobación rápida antes de que el archivo llegue al disco, sin construir una `Engine`.

## Mascota del proyecto

El paquete `pet` embebe la SVG de la mascota del proyecto, Sentinel Gopher (哨兵鼠), en tiempo de compilación mediante `go:embed`, sin dependencias de terceros y sin leer archivos en tiempo de ejecución:

```go
func SVG() []byte         // bytes SVG sin procesar; el slice se comparte y el llamador no debe modificarlo
func Handler() http.Handler // se sirve como image/svg+xml, Cache-Control de un día
func Banner() string      // banner de texto plano apto para terminal, con salto de línea final
```

```go
log.Println(pet.Banner())              // imprimir al arrancar
http.Handle("/pet.svg", pet.Handler()) // montar en una ruta de depuración
```

`Handler` usa internamente `http.ServeContent`, por lo que incluye `Content-Length` y admite `Range` y `HEAD`; un `w.Write` directo supera el búfer de sondeo de 2 KiB de `net/http` y degrada a una respuesta chunked.

## Ejemplo de detector personalizado

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "contenido malicioso detectado",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
