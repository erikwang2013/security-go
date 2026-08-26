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
