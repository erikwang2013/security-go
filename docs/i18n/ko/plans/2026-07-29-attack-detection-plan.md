# Attack Detection 패키지 — 구현 계획

> **에이전트 작업자를 위한 안내:** 필수 하위 스킬: superpowers:subagent-driven-development(권장) 또는 superpowers:executing-plans를 사용하여 이 계획을 작업 단위로 구현하세요.

**목표:** 5대 카테고리에 걸친 32개 감지기, 3가지 플러그형 저장 백엔드, 통합 Engine 등록소를 갖춘 순수 Go 공격 탐지 라이브러리 구축. **상태: 완료 (2026-07-29).**

**아키텍처:** 플랫 인터페이스 설계 — 모든 감지기는 `Detector`(Name + Detect)를 구현합니다. 사전 컴파일된 정규식 패턴. Engine은 등록소, 이름별 조회, 전체 HTTP 요청 스캔을 위한 `DetectRequest`를 제공합니다. RegisterAll은 `all/all.go`(별도 패키지)에 있습니다.

**기술 스택:** Go 1.21+, 표준 라이브러리 `regexp` + `net/http`, Redis 백엔드용 `go-redis`(선택적 서브모듈 `storage/redis/`).

---

### 작업 1: Go 모듈 및 핵심 타입 초기화

**파일:**
- 생성: `go.mod`
- 생성: `security.go`

- [x] **1단계: Go 모듈 초기화**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **2단계: security.go 생성 — Result, Severity, Detector interface, Engine**

```go
package security

import "net/http"

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type Result struct {
	Name     string
	Detected bool
	Message  string
	Severity Severity
	Details  map[string]interface{}
}

type Detector interface {
	Name() string
	Detect(input string) *Result
}

type Engine struct {
	detectors map[string]Detector
}

func NewEngine() *Engine {
	return &Engine{detectors: make(map[string]Detector)}
}

func (e *Engine) Register(d Detector) {
	e.detectors[d.Name()] = d
}

func (e *Engine) Detect(name, input string) *Result {
	if d, ok := e.detectors[name]; ok {
		return d.Detect(input)
	}
	return nil
}

func (e *Engine) DetectAll(input string) []*Result {
	var results []*Result
	for _, d := range e.detectors {
		if r := d.Detect(input); r != nil && r.Detected {
			results = append(results, r)
		}
	}
	return results
}

func (e *Engine) DetectRequest(r *http.Request) []*Result {
	var results []*Result
	inputs := collectRequestInputs(r)
	for _, input := range inputs {
		results = append(results, e.DetectAll(input)...)
	}
	return results
}

func collectRequestInputs(r *http.Request) []string {
	var inputs []string
	inputs = append(inputs, r.URL.String())
	inputs = append(inputs, r.URL.Query().Encode())
	for key, vals := range r.Header {
		for _, v := range vals {
			inputs = append(inputs, key+": "+v)
		}
	}
	for _, c := range r.Cookies() {
		inputs = append(inputs, c.Name+"="+c.Value)
	}
	return inputs
}
```

- [x] **3단계: 빌드** — `go build ./...`
- [x] **4단계: 커밋** — `feat: initialize Go module with core types and Engine`

---

### 작업 2: 저장 백엔드 인터페이스 및 Memory

**파일:**
- 생성: `storage/storage.go`
- 생성: `storage/memory.go`

- [x] **1단계: storage/storage.go** — Backend 인터페이스 (Incr, Get, Block, IsBlocked, Close)
- [x] **2단계: storage/memory.go** — TTL 정리 goroutine이 있는 sync.Map 기반 구현
- [x] **3단계: 빌드** — `go build ./storage/...`
- [x] **4단계: 커밋** — `feat: add storage interface and memory backend`

---

### 작업 3: 파일 및 Redis 저장소

**파일:**
- 생성: `storage/file.go`
- 생성: `storage/redis.go`
- 수정: `go.mod` (go-redis 의존성 추가)

- [x] **1단계: storage/file.go** — 지연 flush 방식의 JSON 파일 영속화
- [x] **2단계: storage/redis.go** — go-redis/v9를 사용한 Redis 백엔드
- [x] **3단계: 빌드** — `go build ./storage/...`
- [x] **4단계: 커밋** — `feat: add file and redis storage backends`

---

### 작업 4: 주입 감지기 — XSS, SQL

**파일:**
- 생성: `injection/xss.go`
- 생성: `injection/sql.go`

- [x] **1단계: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS 패턴
- [x] **2단계: injection/sql.go** — UNION SELECT(`/**/` 우회 포함), sleep/benchmark, 부울 블라인드, 스키마 열거, 저장 프로시저
- [x] **3단계: 빌드** — `go build ./injection/...`
- [x] **4단계: 커밋** — `feat: add XSS and SQL injection detectors`

---

### 작업 5: 주입 감지기 — Command, NoSQL, LDAP, XPATH

**파일:**
- 생성: `injection/command.go`
- 생성: `injection/nosql.go`
- 생성: `injection/ldap.go`
- 생성: `injection/xpath.go`

- [x] **1단계: injection/command.go** — 백틱, `$()`, 파이프, `/dev/tcp`, PHP exec 함수
- [x] **2단계: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, 인증 우회
- [x] **3단계: injection/ldap.go** — 필터 연산자 `(`, `)`, `&`, `|`, `*`
- [x] **4단계: injection/xpath.go** — 부울 우회, string-length, count
- [x] **5단계: 빌드 및 커밋**

---

### 작업 6: 주입 감지기 — JNDI, SSI, GraphQL, SSTI

**파일:**
- 생성: `injection/jndi.go`
- 생성: `injection/ssi.go`
- 생성: `injection/graphql.go`
- 생성: `injection/ssti.go`

- [x] **1단계: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, rmi/dns 프로토콜
- [x] **2단계: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **3단계: injection/graphql.go** — `__schema`, `__type`, 심층 중첩 쿼리, mutation
- [x] **4단계: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO
- [x] **5단계: 빌드 및 커밋**

---

### 작업 7: 프로토콜 감지기 — SSRF, XXE, 헤더 주입

**파일:**
- 생성: `protocol/ssrf.go`
- 생성: `protocol/xxe.go`
- 생성: `protocol/header_injection.go`

- [x] **1단계: protocol/ssrf.go** — 내부 IP, 169.254.169.254, IPv6 루프백, gopher/dict
- [x] **2단계: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, 매개변수 엔티티, DOCTYPE
- [x] **3단계: protocol/header_injection.go** — CRLF, Set-Cookie/Location 주입
- [x] **4단계: 빌드 및 커밋**

---

### 작업 8: 프로토콜 감지기 — Host Header, 요청 스머글링, 오픈 리다이렉트, CORS, WebSocket, DNS 리바인딩

**파일:**
- 생성: `protocol/host_header.go`
- 생성: `protocol/request_smuggling.go`
- 생성: `protocol/open_redirect.go`
- 생성: `protocol/cors.go`
- 생성: `protocol/websocket.go`
- 생성: `protocol/dns_rebinding.go`

- [x] **1단계: 프로토콜 감지기 6개 전부** — 감지기별 파일 하나, 사전 컴파일된 정규식 패턴
- [x] **2단계: 빌드 및 커밋**

---

### 작업 9: HTTP 검증 감지기

**파일:**
- 생성: `httpval/method.go`
- 생성: `httpval/body_size.go`
- 생성: `httpval/content_type.go`
- 생성: `httpval/csrf_origin.go`
- 생성: `httpval/ip_blacklist.go`

- [x] **1단계: httpval/method.go** — GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH 화이트리스트
- [x] **2단계: httpval/body_size.go** — 최대 크기 검사, 기본 10MB
- [x] **3단계: httpval/content_type.go** — MIME 화이트리스트
- [x] **4단계: httpval/csrf_origin.go** — 크로스 오리진 Origin과 Host 일치 검사
- [x] **5단계: httpval/ip_blacklist.go** — 윈도우 레이트 리밋(5/60s → 15분 차단), storage.Backend 사용
- [x] **6단계: 빌드 및 커밋**

---

### 작업 10: 데이터/직렬화 감지기

**파일:**
- 생성: `data/deserialization.go`
- 생성: `data/csv_injection.go`
- 생성: `data/mail_header.go`
- 생성: `data/jwt_attack.go`
- 생성: `data/prototype_pollution.go`

- [x] **1단계: data/deserialization.go** — PHP `O:숫자:`, `C:숫자:`, unserialize(), 매직 메서드
- [x] **2단계: data/csv_injection.go** — `=cmd|`, `@SUM(`, `+`, `-` 수식 접두사
- [x] **3단계: data/mail_header.go** — Bcc/Cc/From/To 주입, MIME multipart
- [x] **4단계: data/jwt_attack.go** — alg:none, kid 경로 순회, 빈 서명(구조적 디코딩)
- [x] **5단계: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **6단계: 빌드 및 커밋**

---

### 작업 11: 파일 및 민감 데이터 감지기

**파일:**
- 생성: `file/path_traversal.go`
- 생성: `file/upload.go`
- 생성: `file/data_leak.go`

- [x] **1단계: file/path_traversal.go** — `../`, `..\\`, php://filter, null 바이트, URL 인코딩 우회
- [x] **2단계: file/upload.go** — 확장자 화이트리스트 + PHP 태그 콘텐츠 스캔
- [x] **3단계: file/data_leak.go** — 신용카드, AWS 키, 개인 키, DB 연결 문자열, API 토큰, JWT 시크릿
- [x] **4단계: 빌드 및 커밋**

---

### 작업 12: Engine 통합 — RegisterAll

**파일:**
- 수정: `security.go`

- [x] **1단계: RegisterAll() 추가** — 내장 감지기 32개 전체 등록
- [x] **2단계: 빌드** — `go build ./...`
- [x] **3단계: 커밋** — `feat: add RegisterAll for built-in detectors`

---

### 작업 13: 테스트

**파일:**
- 생성: `security_test.go`
- 생성: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- 생성: `protocol/ssrf_test.go`
- 생성: `file/path_traversal_test.go`, `data_leak_test.go`
- 생성: `data/jwt_attack_test.go`
- 생성: `storage/memory_test.go`

- [x] **1단계: 테스트 작성** — 각각 긍정/부정 테스트 케이스 포함
- [x] **2단계: 실행** — `go test ./... -v`
- [x] **3단계: 커밋** — `test: add core engine and detector tests`

---

### 작업 14: 구현 후 코드 리뷰 및 수정 (2026-07-29)

- [x] **전면 코드 리뷰** — Go 소스 파일 42개, 8개 패키지
- [x] **Bug 수정 #1** — `storage/file.go`: JSON 직렬화 오류가 조용히 무시됨 → 오류를 검사하고 반환하도록 수정
- [x] **Bug 수정 #2** — `httpval/content_type.go`: 빈 AllowList가 모든 Content-Type을 허용 → deny-all 기본값
- [x] **Bug 수정 #3** — `protocol/xxe.go`: `&[a-z]+;`가 정상 HTML 엔티티를 오탐 → 알려진 악성 프로토콜 목록으로 축소
- [x] **httpval 테스트 추가 작성** — 테스트 케이스 32개, 5개 감지기(BodySize, ContentType, CSRFOrigin, IPBlacklist, Method) 커버
- [x] **전체 테스트** — `go test -count=1 ./...` 7/7 패키지 통과, `go vet` 경고 0건

---

## 실제 구현과 계획의 차이 (Actual vs Planned Deviations)

| 계획 | 실제 | 이유 |
|------|------|------|
| RegisterAll이 `security.go`에 | `all/all.go` 독립 패키지 | 순환 참조 방지, httpval은 storage에 의존하지만 다른 감지기는 의존하지 않음 |
| Redis가 루트 go.mod에 | `storage/redis/` 서브모듈 | 선택적 의존성 격리 |
| Receiver 통일 포인터 | protocol 패키지가 값 수신자 사용 | ✅ v2 리뷰에서 전부 포인터 수신자로 변경됨 |
| 작업 4-12 빌드 및 커밋 | 단계별 커밋 안 함 | 모든 코드를 한 번에 구현 |

## 테스트 커버리지 요약

| 패키지 | 테스트 파일 | 테스트 수 |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (없음) | 0 |

> 전체 보고서는 [코드 리뷰 보고서 v2](../reports/2026-07-29-code-review-report-v2.md)를 참조하세요

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
