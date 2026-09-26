# Security Go — API 인터페이스 문서

이 문서는 `security-go`의 모든 공개 API 인터페이스를 정리한 것입니다: 핵심 타입, `Detector` 인터페이스, `Engine` 등록소, 저장 백엔드 인터페이스 및 HTTP 검증기 생성자.

## 핵심 타입

### Result

각 감지기가 반환하는 감지 결과 구조체:

```go
type Result struct {
    Name     string                 // 감지기 이름
    Detected bool                   // 공격 탐지 여부
    Message  string                 // 결과 설명
    Severity Severity               // 심각도
    Details  map[string]interface{} // 추가 세부 정보
}
```

### Severity

심각도 등급:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 낮은 위험
    SeverityMedium                   // 중간 위험
    SeverityHigh                     // 높은 위험
    SeverityCritical                 // 심각
)
```

## Detector 인터페이스

모든 감지기는 이 인터페이스를 구현해야 합니다:

```go
type Detector interface {
    Name() string                // 감지기 고유 이름
    Detect(input string) *Result // 입력에 대해 탐지를 수행하고 결과를 반환
}
```

## Engine 등록소

`Engine`은 통합 진입점으로, 이름별로 감지기를 등록하고 관리합니다:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 빈 Engine 생성
func (e *Engine) Register(d Detector)             // 감지기 등록
func (e *Engine) Detect(name, input string) *Result // 이름으로 단일 입력 감지
func (e *Engine) DetectAll(input string) []*Result  // 전체 감지(Detected=true만 반환)
func (e *Engine) DetectRequest(r *http.Request) []*Result // 전체 HTTP 요청 감지
```

`DetectRequest`는 요청의 URL, Query, Headers, Cookies를 자동으로 수집하여 입력으로 사용합니다. 각 입력은 URL 디코딩 후 다시 스캔되므로 `%3Cscript%3E` 같은 인코딩된 페이로드로 탐지를 우회할 수 없습니다.

## 등록 진입점

```go
// all 패키지는 모든 무설정 감지기(27개)를 한 번에 등록합니다
all.RegisterAll(engine)
```

## 도우미 함수

```go
// FirstMatch는 input에 처음 일치하는 패턴 문자열을 반환하고, 모두 일치하지 않으면 ("", false)를 반환합니다
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

사용자 정의 감지기는 내장된 사전 컴파일 패턴을 재사용할 수 있어 정규식을 다시 컴파일하지 않아도 됩니다.

## 저장 백엔드 인터페이스

`httpval.IPBlacklist`는 이 인터페이스를 통해 플러그형 저장소를 사용합니다:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 윈도우 내 카운트 +1
    Get(key string) (int, error)                          // 카운트 읽기
    Block(key string, duration time.Duration) error       // 지정한 시간 동안 차단
    IsBlocked(key string) (bool, error)                   // 차단 여부
    Close() error                                         // 종료하고 리소스 해제
}
```

구현:

| 백엔드 | 설명 |
|------|------|
| `storage.NewMemory() *Memory` | 메모리 구현, `sync.Mutex` + map, 30초마다 만료 항목 자동 정리 |
| `storage.NewFile(path) (*File, error)` | JSON 파일 영속화, 30초마다 자동 저장 + Close 시 flush |
| `redis.New(addr, password string, db int) *Backend` | Redis 서브모듈, Pipeline Incr + TTL, `go-redis/v9` 필요 |

## HTTP 검증기

```go
// HTTP 메서드 화이트리스트 검증
e.Register(&httpval.Method{})

// 요청 본문 크기 제한(기본 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 화이트리스트(빈 화이트리스트 = 모두 거부)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 검증(크로스 도메인 요청은 Origin과 Host 일치 확인)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 블랙리스트(윈도우 내 N회 공격 시 자동 차단, 기본 5회/60초 → 15분 차단)
bl := httpval.NewIPBlacklist(mem) // mem은 임의의 storage.Backend 구현체
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### JSON 중첩 깊이 및 Cookie 속성

| 생성자 | 설명 |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | JSON 본문을 스트림 스캔하여 중첩 깊이(기본 32)나 요소 수가 한도를 넘으면 `nested_depth`를 보고합니다. 잘못되었거나 잘린 JSON은 절대 일치하지 않습니다 |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | `Set-Cookie` 하나를 검증: 누락된 속성, 초과 길이 값(`MaxValueLen`), 빈 값(`RequireNonEmpty`) |

## 세션 보안

`session` 패키지는 **클라이언트 하이재킹**, **데이터 변조**, **원격 로그인**을 탐지합니다. 완전한 `*http.Request`(token, 클라이언트 IP, User-Agent)와 애플리케이션이 준비한 저장소 및 키가 필요하므로 `Engine`에 등록하지 않고 미들웨어/함수로 직접 호출합니다.

### Store 인터페이스

세션 바인딩은 `storage.Backend`(카운트와 차단만 지원)로 표현할 수 없으므로 `session`은 자체적으로 작은 인터페이스를 제공합니다:

```go
type Store interface {
    Save(key string, value []byte, ttl time.Duration) error
    Load(key string) ([]byte, error)   // 없거나 만료된 경우 (nil, nil) 반환
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // 메모리 구현, 30초마다 만료 항목 정리, Close 시 정리 중단
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // 세션 생성 시점의 클라이언트 IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // 기기 지문(X-Device-Fingerprint 헤더)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // 매 Check마다 슬라이딩 갱신
}
```

### Tracker

감지기 이름 `session_guard`(`Tracker.Name()` 참조).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // 세션 수명, 기본 30m, 매 Check마다 슬라이딩 갱신
    SubnetBits        int                        // 동일 지역 판정 접두사, 기본 24(IPv6는 자동 +24)
    CountryOf         func(ip string) string     // 선택적 GeoIP 훅; nil이면 국가 판정 생략
    KnownNets         int                        // Observe가 사용자별로 보관하는 로그인 네트워크 대역 수, 기본 8
    KnownNetTTL       time.Duration              // 로그인 네트워크 대역 보관 기간, 기본 90일
    TokenSource       func(*http.Request) string // 기본 DefaultTokenSource
    TrustProxyHeaders bool                       // 기본 false
    FailClosed        bool                       // 기본 false
    Failures          int                        // 윈도우 내 token을 잠그는 실패 횟수 임계값, 기본 5
    FailureWindow     time.Duration              // 실패 카운트 보관 기간, 초과분은 집계하지 않음, 기본 5m
    Lockout           time.Duration              // 임계값 최초 도달 시 잠금 시간, 이후 매번 두 배, 기본 15m
    MaxLockout        time.Duration              // 잠금 두 배 증가의 상한, 기본 24h
    BackoffWindow     time.Duration              // 에스컬레이션 카운트 보관 기간, 기본 24h
    StuffingLimit     int                        // 동일 IP가 실패할 수 있는 서로 다른 식별자 수 상한, 기본 10
}
```

| 메서드 | 설명 |
|------|------|
| `NewTracker(store) *Tracker` | 생성 후 기본값을 채웁니다 |
| `Issue(token, r) error` | 로그인 성공 후 token → IP 대역 / UA / 지문을 바인딩; 빈 token은 오류를 반환 |
| `Check(r) *Result` | 요청마다 검증하고 적중 시 `Detected: true` 반환; 통과 시 슬라이딩 갱신 |
| `Observe(user, r) *Result` | 로그인 시 해당 사용자의 과거 로그인 네트워크 대역과 비교하여 새 대역이 나타나면 경고; 최초 로그인은 기준선이 없어 경고하지 않음 |
| `Guard(http.Handler) http.Handler` | 미들웨어 래퍼로, `Check` 적중 시 401 반환 |
| `Revoke(token) error` | 로그아웃, 세션 즉시 무효화 |
| `DefaultTokenSource(r) string` | `Authorization: Bearer <token>` 우선, 그다음 `session` Cookie |
| `RecordFailure(identity, r) error` | 로그인 실패를 1회 계산(identity는 사용자 이름 등 인증 키, r은 클라이언트 IP 제공). 윈도우 내 `Failures`(기본 5회 / 5분)에 도달하면 잠그고, 매번 두 배로 늘어 `MaxLockout`(기본 24시간)까지 |
| `CheckLogin(identity, r) *Result` | 로그인 시도의 사전 검사: 식별자가 잠겨 있으면 `token_locked`, 클라이언트 IP가 이미 `StuffingLimit`(기본 10)개의 서로 다른 식별자에 실패했으면 `credential_stuffing` — 둘 다 Critical |
| `GuardLogin(next, identity) http.Handler` | 인증 엔드포인트용 미들웨어: 해당 시 `Retry-After`와 함께 429. 핸들러 이후 401은 실패로 계산하고 2xx는 횟수를 초기화합니다 |
| `IsLocked(token) (bool, time.Time)` | 토큰이 잠겼는지와 해제 시각. 저장소 오류는 잠기지 않은 것으로 처리 |
| `ClearFailures(token) error` | 로그인 성공 시 실패 횟수를 초기화합니다(잠금은 자체 타이머로 동작하며 해제되지 않음) |

`Details["reason"]` 값:

| reason | 트리거 조건 | 심각도 |
|--------|---------|---------|
| `missing_token` | 요청에 token이 없음 | High |
| `unknown_token` | token이 발급되지 않았거나 `Revoke`되었거나 만료됨 | High |
| `token_locked` | 윈도우 내 실패 횟수가 임계값 도달, 토큰 잠김 | Critical |
| `credential_stuffing` | 하나의 IP가 윈도우 내 `StuffingLimit`개의 서로 다른 식별자에 실패 | Critical |
| `client_hijack` | UA 변경 또는 기기 지문 변경 | Critical |
| `remote_login` | `CountryOf`가 국가 간 이동(Critical) / IP 대역 간 이동(High)으로 판정, `Check`와 `Observe` 공용 | Critical / High |
| `store_error` | 저장소 읽기 실패이고 `FailClosed = true` | High |

> `TrustProxyHeaders`는 기본적으로 비활성화됩니다: `X-Forwarded-For` / `X-Real-IP`는 클라이언트가 제어할 수 있으므로 활성화하면 하이재커가 바인딩된 IP를 위조할 수 있습니다. 자체 리버스 프록시 뒤에서만 활성화하세요.
> `FailClosed`는 기본적으로 비활성화됩니다(저장소 장애 시 통과), `httpval.IPBlacklist`와 동일합니다. 저장 키는 token의 SHA-256이므로 저장소가 유출되어도 사용 가능한 token을 직접 얻을 수 없습니다.

### Signer

감지기 이름 `data_tamper`(`Signer.Name()` 참조).

```go
type Signer struct {
    Secret  []byte           // 공유 HMAC 키, crypto/rand로 생성
    MaxSkew time.Duration    // 타임스탬프 허용 편차, 기본 5m
    Nonces  storage.Backend  // 선택 사항: 값이 있으면 윈도우 카운터로 서명 재전송을 차단(인스턴스 간 공유, Redis 재사용)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // 파라미터 변경/키 불일치/시간 초과/재전송
```

파라미터는 `url.Values.Encode()`로 정규화되며(정렬 + 이스케이프), map 순서는 결과에 영향을 주지 않습니다. 검증 순서는 타임스탬프 → 서명 → nonce 카운트이므로 위조 서명은 유효한 nonce를 소모할 수 없습니다; `Nonces`가 nil이면 타임스탬프 윈도우로만 재전송을 제한할 수 있습니다.

`Details["reason"]` 값: `signer_not_configured`(Critical), `signature_mismatch`(Critical), `replay`(Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future`(High).

## 파일 업로드 도우미 함수

업로드 감지는 감지기로 등록하는 것 외에도 직접 호출할 수 있는 두 가지 도우미 함수를 제공합니다:

```go
// HasMaliciousExt는 파일 확장자가 화이트리스트(15종) 밖인지 판단하며, 확장자가 없으면 true를 반환합니다
func HasMaliciousExt(filename string) bool

// CheckExtension은 위와 같은 로직이지만 전체 *Result(심각도와 설명 포함)를 반환합니다
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

파일이 디스크에 기록되기 전에 `Engine`을 구성하지 않고 빠르게 사전 검사할 때 사용합니다.

## 프로젝트 마스코트

`pet` 패키지는 `go:embed`로 컴파일 시점에 프로젝트 마스코트 Sentinel Gopher(哨兵鼠)의 SVG를 내장합니다. 서드파티 의존성을 추가하지 않고 런타임에 파일을 읽지도 않습니다:

```go
func SVG() []byte         // 원시 SVG 바이트; 슬라이스를 공유하므로 호출자가 수정해서는 안 됩니다
func Handler() http.Handler // image/svg+xml로 제공, Cache-Control 1일
func Banner() string      // 터미널 친화적 일반 텍스트 배너, 끝에 개행 포함
```

```go
log.Println(pet.Banner())              // 시작 시 출력
http.Handle("/pet.svg", pet.Handler()) // 디버그 라우트에 연결
```

`Handler`는 내부적으로 `http.ServeContent`를 사용하므로 `Content-Length`를 포함하고 `Range`와 `HEAD`를 지원합니다. 직접 `w.Write`를 호출하면 `net/http`의 2 KiB 스니핑 버퍼를 넘겨 chunked 응답으로 퇴화합니다.

## 사용자 정의 감지기 예시

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "악성 콘텐츠 감지됨",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
