# Security Go — Документация API

В этом документе собраны все публичные API-интерфейсы `security-go`: основные типы, интерфейс `Detector`, реестр `Engine`, интерфейс бэкенда хранилища и конструкторы HTTP-валидаторов.

## Основные типы

### Result

Структура результата обнаружения, возвращаемая каждым детектором:

```go
type Result struct {
    Name     string                 // имя детектора
    Detected bool                   // обнаружена ли атака
    Message  string                 // описание результата
    Severity Severity               // уровень серьёзности
    Details  map[string]interface{} // дополнительные детали
}
```

### Severity

Уровни серьёзности:

```go
type Severity int

const (
    SeverityLow      Severity = iota // низкий риск
    SeverityMedium                   // средний риск
    SeverityHigh                     // высокий риск
    SeverityCritical                 // критический
)
```

## Интерфейс Detector

Все детекторы обязаны реализовывать этот интерфейс:

```go
type Detector interface {
    Name() string                // уникальное имя детектора
    Detect(input string) *Result // выполняет обнаружение по входным данным и возвращает результат
}
```

## Реестр Engine

`Engine` — единая точка входа, регистрирует и управляет детекторами по имени:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // создаёт пустой Engine
func (e *Engine) Register(d Detector)             // регистрирует детектор
func (e *Engine) Detect(name, input string) *Result // обнаруживает один вход по имени
func (e *Engine) DetectAll(input string) []*Result  // полное обнаружение (возвращает только Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // обнаруживает полный HTTP-запрос
```

`DetectRequest` автоматически собирает URL, Query, Headers и Cookies запроса в качестве входных данных. Каждый вход дополнительно проверяется после URL-декодирования, поэтому закодированные полезные нагрузки вроде `%3Cscript%3E` не обходят обнаружение.

## Точка регистрации

```go
// пакет all регистрирует все детекторы без конфигурации (27) одним вызовом
all.RegisterAll(engine)
```

## Вспомогательная функция

```go
// FirstMatch возвращает первую строку шаблона, совпавшую с input; ("", false), если совпадений нет
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Собственные детекторы могут переиспользовать встроенные предкомпилированные шаблоны, не компилируя регулярные выражения заново.

## Интерфейс бэкенда хранилища

`httpval.IPBlacklist` использует подключаемое хранилище через этот интерфейс:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // увеличивает счётчик внутри окна
    Get(key string) (int, error)                          // читает счётчик
    Block(key string, duration time.Duration) error       // блокирует на указанное время
    IsBlocked(key string) (bool, error)                   // заблокирован ли уже
    Close() error                                         // закрывает и освобождает ресурсы
}
```

Реализации:

| Бэкенд | Описание |
|------|------|
| `storage.NewMemory() *Memory` | реализация в памяти, `sync.Mutex` + map, автоматическая очистка устаревших записей каждые 30 с |
| `storage.NewFile(path) (*File, error)` | JSON-персистентность на диск, автосохранение каждые 30 с + flush при Close |
| `redis.New(addr, password string, db int) *Backend` | подмодуль Redis, Pipeline Incr + TTL, требуется `go-redis/v9` |

## HTTP-валидаторы

```go
// проверка белого списка HTTP-методов
e.Register(&httpval.Method{})

// ограничение размера тела запроса (по умолчанию 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// белый список Content-Type (пустой список = отклонять всё)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// проверка CSRF Origin (кросс-доменные запросы требуют совпадения Origin и Host)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP-чёрный список (автоблокировка после N атак в окне; по умолчанию 5/60 с → блокировка на 15 минут)
bl := httpval.NewIPBlacklist(mem) // mem — любая реализация storage.Backend
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
    Load(key string) ([]byte, error)   // возвращает (nil, nil), если запись отсутствует или истекла
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // реализация в памяти; очищает истёкшие записи каждые 30 с, Close останавливает очистку
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // IP-адрес клиента на момент создания сессии
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // отпечаток устройства (заголовок X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // продлевается скользящим образом при каждом Check
}
```

### Tracker

Имя детектора `session_guard` (см. `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // время жизни сессии, по умолчанию 30m, продлевается скользящим образом при каждом Check
    SubnetBits        int                        // префикс определения одной локации, по умолчанию 24 (для IPv6 автоматически +24)
    CountryOf         func(ip string) string     // необязательный хук GeoIP; при nil проверка страны пропускается
    KnownNets         int                        // число сетей входа, хранимых Observe на пользователя, по умолчанию 8
    KnownNetTTL       time.Duration              // сколько хранится сеть входа, по умолчанию 90 дней
    TokenSource       func(*http.Request) string // по умолчанию DefaultTokenSource
    TrustProxyHeaders bool                       // по умолчанию false
    FailClosed        bool                       // по умолчанию false
    Failures          int                        // порог неудач, блокирующий token внутри окна, по умолчанию 5
    FailureWindow     time.Duration              // сколько хранятся неудачи; более старые не учитываются, по умолчанию 5m
    Lockout           time.Duration              // длительность блокировки при первом достижении порога, удваивается при каждом следующем, по умолчанию 15m
    MaxLockout        time.Duration              // потолок удвоения блокировки, по умолчанию 24h
    BackoffWindow     time.Duration              // сколько хранятся счётчики эскалации, по умолчанию 24h
    StuffingLimit     int                        // максимум различных идентификаторов, против которых может ошибиться один IP, по умолчанию 10
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

Имя детектора `data_tamper` (см. `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // общий HMAC-ключ, генерируйте через crypto/rand
    MaxSkew time.Duration    // допустимое отклонение временной метки, по умолчанию 5m
    Nonces  storage.Backend  // необязательно: если не nil, оконный счётчик блокирует повтор подписи (между экземплярами, переиспользуйте Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // параметры изменены / ключ не совпадает / истёк / повтор
```

Параметры нормализуются через `url.Values.Encode()` (сортировка + экранирование), порядок ключей в map не влияет на результат. Порядок проверки — временная метка → подпись → счётчик nonce, поэтому подделанная подпись не может израсходовать легитимный nonce; при `Nonces` = nil воспроизведение ограничивается только окном временной метки.

`Details["reason"]` принимает значения: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Вспомогательные функции загрузки файлов

Помимо регистрации в качестве детектора, обнаружение загрузок экспортирует две вспомогательные функции, которые можно вызывать напрямую:

```go
// HasMaliciousExt сообщает, находится ли расширение файла вне белого списка (15 записей); при отсутствии расширения возвращает true
func HasMaliciousExt(filename string) bool

// CheckExtension использует ту же логику, но возвращает полный *Result (с серьёзностью и описанием)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Используйте её для быстрой предварительной проверки до записи файла на диск, без создания `Engine`.

## Талисман проекта

Пакет `pet` встраивает талисман проекта Sentinel Gopher(哨兵鼠) как SVG на этапе компиляции через `go:embed`. Он не добавляет сторонних зависимостей и не читает файлы во время работы:

```go
func SVG() []byte         // сырые байты SVG; срез общий, вызывающий не должен его изменять
func Handler() http.Handler // отдаётся как image/svg+xml, Cache-Control на сутки
func Banner() string      // баннер в виде простого текста, удобного для терминала, с переводом строки в конце
```

```go
log.Println(pet.Banner())              // печатается при запуске
http.Handle("/pet.svg", pet.Handler()) // вешается на отладочный маршрут
```

Внутри `Handler` используется `http.ServeContent`, поэтому ответ несёт `Content-Length` и поддерживает `Range` и `HEAD`; прямой `w.Write` превысил бы 2 KiB буфер сниффинга `net/http` и выродился бы в chunked-ответ.

### Поза: определяется результатами обнаружения

Талисман — не статичная картинка: щит, радар и лупа меняют цвет по результатам проверки, поэтому он сам служит индикатором уровня угрозы:

```go
type Mood int

const (
    Calm     Mood = iota // проверка ничего не нашла
    Watchful             // что-то сработало, но ничего High / Critical
    Alarmed              // хотя бы один High или Critical, требует реакции
)

func MoodOf(results []*security.Result) Mood  // определяется самым серьёзным попаданием
func SVGFor(m Mood) []byte                    // графика для этой позы; неизвестное значение откатывается к Calm
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler
```

`MoodOf` учитывает только результаты с `Detected` — детектор проставляет `Severity` даже когда ничего не нашёл, поэтому одна лишь серьёзность не должна поднимать тревогу. Побеждает самое серьёзное попадание, независимо от порядка результатов.

Подключите движок — и получите живую картину состояния угрозы:

```go
e := security.NewEngine()
all.RegisterAll(e)

http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` добавляет `Cache-Control: no-store` — в отличие от статичного `Handler`, его вывод меняется от проверки к проверке, и суточное кеширование отдавало бы устаревшую позу.

## Пример собственного детектора

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "обнаружено вредоносное содержимое",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
