# Security Go — API 인터페이스 문서

이 문서는 `security-go`의 모든 공개 API 인터페이스를 정리한 것입니다: 핵심 타입, `Detector` 인터페이스, `Engine` 등록소, 저장 백엔드 인터페이스 및 HTTP 검증기 생성자.

## 핵심 타입

### Result

각 감지기가 반환하는 감지 결과 구조체:

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

심각도 등급:

```go
type Severity int

const (
    SeverityLow      Severity = iota // 低风险
    SeverityMedium                   // 中风险
    SeverityHigh                     // 高风险
    SeverityCritical                 // 严重
)
```

## Detector 인터페이스

모든 감지기는 이 인터페이스를 구현해야 합니다:

```go
type Detector interface {
    Name() string                // 检测器唯一名称
    Detect(input string) *Result // 对输入执行检测，返回结果
}
```

## Engine 등록소

`Engine`은 통합 진입점으로, 이름별로 감지기를 등록하고 관리합니다:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // 创建空 Engine
func (e *Engine) Register(d Detector)             // 注册检测器
func (e *Engine) Detect(name, input string) *Result // 按名称检测单个输入
func (e *Engine) DetectAll(input string) []*Result  // 全量检测（仅返回 Detected=true）
func (e *Engine) DetectRequest(r *http.Request) []*Result // 检测完整 HTTP 请求
```

`DetectRequest`는 요청의 URL, Query, Headers, Cookies를 자동으로 수집하여 입력으로 사용합니다.

## 등록 진입점

```go
// all 包提供一键注册全部零配置检测器（27 个）
all.RegisterAll(engine)
```

## 저장 백엔드 인터페이스

`httpval.IPBlacklist`는 이 인터페이스를 통해 플러그형 저장소를 사용합니다:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // 窗口内计数 +1
    Get(key string) (int, error)                          // 读取计数
    Block(key string, duration time.Duration) error       // 封禁指定时长
    IsBlocked(key string) (bool, error)                   // 是否已封禁
    Close() error                                         // 关闭并释放资源
}
```

구현:

| 백엔드 | 설명 |
|------|------|
| `storage.NewMemory()` | 메모리 구현, `sync.Mutex` + map, 30초마다 만료 항목 자동 정리 |
| `storage.NewFile(path)` | JSON 파일 영속화, 30초마다 자동 저장 + Close 시 flush |
| `storage/redis` | Redis 서브모듈, Pipeline Incr + TTL, `go-redis/v9` 필요 |

## HTTP 검증기

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

| 메서드 | 설명 |
|------|------|
| `NewTracker(store) *Tracker` | 생성 후 기본값을 채웁니다 |
| `Issue(token, r) error` | 로그인 성공 후 token → IP 대역 / UA / 지문을 바인딩; 빈 token은 오류를 반환 |
| `Check(r) *Result` | 요청마다 검증하고 적중 시 `Detected: true` 반환; 통과 시 슬라이딩 갱신 |
| `Observe(user, r) *Result` | 로그인 시 해당 사용자의 과거 로그인 네트워크 대역과 비교하여 새 대역이 나타나면 경고; 최초 로그인은 기준선이 없어 경고하지 않음 |
| `Guard(http.Handler) http.Handler` | 미들웨어 래퍼로, `Check` 적중 시 401 반환 |
| `Revoke(token) error` | 로그아웃, 세션 즉시 무효화 |
| `DefaultTokenSource(r) string` | `Authorization: Bearer <token>` 우선, 그다음 `session` Cookie |
| `RecordFailure(token) error` | 인증 실패를 1회 계산하며, 윈도우 내 `Failures`(기본 5회 / 5분)에 도달하면 잠금을 기록합니다. `Lockout` 기본 15분 |
| `IsLocked(token) (bool, time.Time)` | 토큰이 잠겼는지와 해제 시각. 저장소 오류는 잠기지 않은 것으로 처리 |
| `ClearFailures(token) error` | 로그인 성공 시 실패 횟수를 초기화합니다(잠금은 자체 타이머로 동작하며 해제되지 않음) |

`Details["reason"]` 값:

| reason | 트리거 조건 | 심각도 |
|--------|---------|---------|
| `missing_token` | 요청에 token이 없음 | High |
| `unknown_token` | token이 발급되지 않았거나 `Revoke`되었거나 만료됨 | High |
| `token_locked` | 윈도우 내 실패 횟수가 임계값 도달, 토큰 잠김 | Critical |
| `client_hijack` | UA 변경 또는 기기 지문 변경 | Critical |
| `remote_login` | `CountryOf`가 국가 간 이동(Critical) / IP 대역 간 이동(High)으로 판정, `Check`와 `Observe` 공용 | Critical / High |
| `store_error` | 저장소 읽기 실패이고 `FailClosed = true` | High |

> `TrustProxyHeaders`는 기본적으로 비활성화됩니다: `X-Forwarded-For` / `X-Real-IP`는 클라이언트가 제어할 수 있으므로 활성화하면 하이재커가 바인딩된 IP를 위조할 수 있습니다. 자체 리버스 프록시 뒤에서만 활성화하세요.
> `FailClosed`는 기본적으로 비활성화됩니다(저장소 장애 시 통과), `httpval.IPBlacklist`와 동일합니다. 저장 키는 token의 SHA-256이므로 저장소가 유출되어도 사용 가능한 token을 직접 얻을 수 없습니다.

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

파라미터는 `url.Values.Encode()`로 정규화되며(정렬 + 이스케이프), map 순서는 결과에 영향을 주지 않습니다. 검증 순서는 타임스탬프 → 서명 → nonce 카운트이므로 위조 서명은 유효한 nonce를 소모할 수 없습니다; `Nonces`가 nil이면 타임스탬프 윈도우로만 재전송을 제한할 수 있습니다.

`Details["reason"]` 값: `signer_not_configured`(Critical), `signature_mismatch`(Critical), `replay`(Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future`(High).

## 사용자 정의 감지기 예시

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
