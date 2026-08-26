# Security Go — 공격 탐지 라이브러리

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API 인터페이스 문서](api.md)

Go 언어로 작성된 공격 탐지 패키지로, **32개의 감지기**, **5대 공격 카테고리**, **3가지 플러그형 저장 백엔드**를 지원합니다. 통합 인터페이스 + 등록소 패턴을 사용하는 순수 탐지 라이브러리로, 모든 Go HTTP 프레임워크에 적용할 수 있습니다.

## 설계 철학

### 핵심 원칙

- **제로 의존성 탐지** — 모든 감지기는 Go 표준 라이브러리 `regexp`만 사용하며 외부 의존성이 없습니다
- **통합 인터페이스** — 각 감지기는 `Detector` 인터페이스(`Name()` + `Detect()`)를 구현하고, `Engine` 등록소를 통해 통합 관리됩니다
- **사전 컴파일된 정규식** — 모든 패턴은 `var` 초기화 시점에 컴파일되어 런타임 오버헤드가 없습니다
- **필요에 따른 구성** — 주입/프로토콜/데이터/파일 감지기는 플러그 앤 플레이 방식; HTTP 검증기는 애플리케이션에서 커스텀 구성이 필요합니다

### 설계 아키텍처

```
                         ┌───────────────────────────────┐
                         │        security.Engine         │
                         │  ┌─────────────────────────┐  │
                         │  │    Detector Registry     │  │
                         │  │   map[string]Detector    │  │
                         │  └─────────────────────────┘  │
                         │                               │
                         │  Detect(name, input)          │
                         │  DetectAll(input)             │
                         │  DetectRequest(*http.Request) │
                         └──────────────┬────────────────┘
                                        │
          ┌─────────────────┬───────────┴───────────┬─────────────────┐
          │                 │                       │                 │
   ┌──────▼──────┐   ┌──────▼──────┐   ┌────────────▼────────┐   ┌───▼───────────┐
   │  injection  │   │  protocol   │   │        data         │   │     file      │
   │   (10 个)   │   │   (9 个)    │   │       (5 个)        │   │    (3 个)     │
   │             │   │             │   │                     │   │               │
   │  xss, sql,  │   │  ssrf, xxe, │   │  deser, csv,        │   │  traversal,   │
   │  command,   │   │  header,    │   │  mail, jwt,         │   │  upload,      │
   │  nosql,     │   │  host,      │   │  proto_poll         │   │  data_leak    │
   │  ldap,      │   │  smuggling, │   │                     │   │               │
   │  xpath,     │   │  redirect,  │   │                     │   │               │
   │  jndi, ssi, │   │  cors, ws,  │   │                     │   │               │
   │  graphql,   │   │  dns_rebind │   │                     │   │               │
   │  ssti       │   │             │   │                     │   │               │
   └─────────────┘   └─────────────┘   └─────────────────────┘   └───────────────┘
                                                                          │
          ┌───────────────────────────────────────────────────────────────┤
          │                                                               │
   ┌──────▼──────────┐                                         ┌──────────▼──────────┐
   │     httpval     │                                         │       storage       │
   │     (5 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘
```

### 데이터 흐름

```
HTTP Request
     │
     ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│ collectInputs│────▶│  DetectAll()    │────▶│  []*Result   │
│ URL, Query,  │     │  逐个检测器调用   │     │  聚合结果     │
│ Headers,     │     │  Detect(input)  │     │              │
│ Cookies      │     └─────────────────┘     └──────────────┘
└──────────────┘
```

### 심각도 등급

| 등급 | 설명 | 대표 시나리오 |
|------|------|---------|
| `SeverityLow` | 낮은 위험 | 허용되지 않은 HTTP 메서드, Content-Type 불일치 |
| `SeverityMedium` | 중간 위험 | CORS 구성 문제, 오픈 리다이렉트, GraphQL 인트로스펙션 |
| `SeverityHigh` | 높은 위험 | XSS, SQL 주입, SSRF, 경로 순회 |
| `SeverityCritical` | 심각 | 명령 주입, JNDI, SSTI, XXE, 데이터 유출 |

## 구현 기능

### 주입형 공격 (10)

| 감지기 | 감지 패턴 |
|--------|---------|
| **XSS** | `<script>`、`on[a-z]+=` 이벤트 핸들러, `javascript:` 가상 프로토콜, SVG/CSS 주입, `eval()`, `document.cookie` |
| **SQL 주입** | `UNION SELECT`(`/**/` 우회 포함), `sleep/benchmark/pg_sleep`, 부울 블라인드, `information_schema` 열거, `xp_cmdshell` |
| **명령 주입** | 백틱, `$()`, 파이프 문자, `/dev/tcp`, PHP `system/exec/shell_exec`, 연쇄 실행 `&&` `;` `\|\|` |
| **NoSQL 주입** | MongoDB `$ne` `$gt` `$regex` `$where` 연산자, `$func`, JSON 키 주입 |
| **LDAP 주입** | 필터 연산자 `(\|(&(!`, `objectClass=*`, URL 인코딩 우회 |
| **XPATH 주입** | 부울 우회 `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, `${lower:j}` 난독화, `${env:}` 환경 변수, `ldap/rmi/dns` 프로토콜 |
| **SSI 주입** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL 주입** | `__schema`/`__type` 인트로스펙션, 심층 중첩 DoS(5계층 이상), `mutation` 감지 |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO 순회, `config/self` 접근 |

### 프로토콜 및 요청 공격 (9)

| 감지기 | 감지 패턴 |
|--------|---------|
| **SSRF** | 내부망 IP(127/10/172.16/192.168), `169.254.169.254`, IPv6 루프백, `gopher/dict/file/ftp` 프로토콜 |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, 매개변수 엔티티 `%entity;`, DOCTYPE 선언 |
| **HTTP 헤더 주입** | CRLF `%0d%0a` / `\r\n`, Set-Cookie/Location/Content-Length 주입 |
| **Host 헤더 공격** | CRLF Host 주입, `X-Forwarded-Host`, `X-Original-URL` 포이즈닝 |
| **요청 스머글링** | Transfer-Encoding/Content-Length 불일치, 이중 TE 헤더, `\x0b` 폴딩 헤더 난독화 |
| **오픈 리다이렉트** | `//evil.com` 프로토콜 상대 URL, `javascript:/data:` 가상 프로토콜 |
| **CORS 우회** | `Origin: null`, `Access-Control-Allow-*` 헤더 주입 |
| **WebSocket 하이재킹** | Upgrade 헤더 주입, null Origin 우회, `ws://` URL |
| **DNS 리바인딩** | Host 헤더 내부망 IP, localhost, TLD 없는 짧은 호스트명 |

### HTTP 프로토콜 계층 검증 (5)

| 감지기 | 설명 |
|--------|------|
| **HTTP 메서드** | GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH만 허용, 그 외는 경고 |
| **요청 본문 크기** | 상한(기본 10MB) 초과 시 경고 |
| **Content-Type** | 구성된 MIME 타입 화이트리스트만 허용 |
| **CSRF Origin** | 크로스 도메인 요청의 Origin과 Host 일치 여부 검사, 추가 화이트리스트 지원 |
| **IP 블랙리스트** | 윈도우 시간 내 N회 공격 시 자동 차단(기본 5회/60초 → 15분 차단), File/Redis/Memory 저장소 지원 |

### 데이터 및 직렬화 공격 (5)

| 감지기 | 감지 패턴 |
|--------|---------|
| **PHP 역직렬화** | `O:숫자:` / `C:숫자:` 직렬화 객체, `unserialize()`, 매직 메서드(`__wakeup`/`__destruct`) |
| **CSV 주입** | `=cmd\|`, `@SUM(`, `+`/`-` 수식 접두사, `HYPERLINK`/`DDE` |
| **메일 헤더 주입** | Bcc/Cc/From/To 주입, MIME multipart, boundary 매개변수 |
| **JWT 공격** | `alg: none` 우회, `kid` 경로 순회, 빈 서명 감지(구조 디코딩 분석) |
| **프로토타입 폴루션** | `__proto__`/`constructor` 키, `__defineGetter__`/`__defineSetter__` |

### 파일 및 민감 데이터 (3)

| 감지기 | 감지 패턴 |
|--------|---------|
| **경로 순회** | `../`, `..\\`, `php://filter`/`php://input`, null 바이트, URL 인코딩 우회, `/etc/passwd` |
| **악성 업로드** | 확장자 화이트리스트(15종) + PHP 태그 `<?php`/`<?=` 콘텐츠 스캔 |
| **데이터 유출** | 신용카드 번호, AWS Access Key, 개인 키 `-----BEGIN`, DB 연결 문자열, API Token, JWT Secret, GitHub PAT |

### 저장 백엔드 (3)

| 백엔드 | 설명 |
|------|------|
| **Memory** | `sync.Mutex` + map, 30초마다 만료 항목 자동 정리 |
| **File** | JSON 파일 영속화, Close 시 flush |
| **Redis** | 독립 서브모듈, Pipeline Incr + TTL, `go-redis/v9` 필요 |

## 사용 방법

### 설치

```bash
go get github.com/erikwang2013/security-go
```

### 빠른 시작

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // 一键注册 27 个零配置检测器

    // 单个检测
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("检测到: %v, 严重程度: %d\n", r.Detected, r.Severity)

    // 全量检测
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### HTTP 요청 감지

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("攻击检测: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP 검증기 구성

```go
// 方法校验
e.Register(&httpval.Method{})

// 请求体大小限制
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 检查
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（自动封禁：5次/60s → 封禁15分钟）
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// 攻击发生时记录
blocked, _ := bl.RecordAttack(clientIP)
```

### 사용자 정의 감지기

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

### 관련 문서

- [API 인터페이스 문서](api.md) — 핵심 타입, Detector/Engine 인터페이스, 저장 백엔드 인터페이스, HTTP 검증기
- [설계 규격](specs/2026-07-29-attack-detection-design.md) — 패키지 구조, 감지기 목록
- [구현 계획](plans/2026-07-29-attack-detection-plan.md) — 단계별 작업 계획과 구현 이탈 대조
- [코드 리뷰 보고서](reports/2026-07-29-code-review-report.md) — Bug 수정, 테스트 커버리지, 아키텍처 평가

---

## 다국어 문서

| 언어 | 문서 |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README.md](../en/README.md) |
| 한국어 | [README.md](README.md) |
| Русский | [README.md](../ru/README.md) |
| Deutsch | [README.md](../de/README.md) |
| Français | [README.md](../fr/README.md) |
| Español | [README.md](../es/README.md) |
| Português | [README.md](../pt/README.md) |
| हिन्दी | [README.md](../hi/README.md) |
| العربية | [README.md](../ar/README.md) |
| বাংলা | [README.md](../bn/README.md) |
| Bahasa Indonesia | [README.md](../id/README.md) |
| 日本語 | [README.md](../ja/README.md) |

문서 색인: [docs/i18n/README.md](../README.md)

---

## 후원 지원

이 프로젝트가 도움이 되었다면 후원으로 지원해 주세요:

| 방식 | QR 코드 |
|------|--------|
| 알리페이 | ![알리페이](images/alipay.png) |
| 위챗페이 | ![위챗페이](images/weixinpay.png) |

### 해외 송금 후원 (은행 송금)

**수취인 정보**

- 수취인 이름: WANG KEXUN
- 수취 계좌 번호: 881015918251

**수취 은행 (ZA Bank)**

- SWIFT Code: `AABLHKHHXXX`
- 은행 이름: ZA Bank Limited
- 은행 번호: 387
- 은행 주소: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**해외 송금 중계 은행 (필요 시)**

> 참고: 이 정보는 해외 송금 중계 은행(중개 은행) 정보이며, 수취 은행 정보가 아닙니다. 송금 은행에 중계 은행 정보 제공이 필요한지 문의하세요.

- 홍콩 달러, 위안화 및 미국 달러 송금 시 중계 은행은 Citibank입니다:
  - 은행 이름: Citibank N.A. Hong Kong
  - SWIFT Code: `CITIHKHXXXX`
  - 은행 번호: 006
  - 지점 이름: Hong Kong Branch
  - 지점 번호: 391
  - 은행 주소: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- 기타 통화 송금 시 중계 은행은 BNY Mellon입니다:
  - 은행 이름: THE BANK OF NEW YORK MELLON
  - SWIFT Code: `IRVTUS3NXXX`
  - 은행 주소: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

전체 영문 문서는 [README-EN.md](../../../README-EN.md)를 참조하세요.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
