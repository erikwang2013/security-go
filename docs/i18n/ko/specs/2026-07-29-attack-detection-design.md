# Attack Detection 패키지 — 설계 규격

## 개요

순수 Go 공격 탐지 라이브러리로, 통합 인터페이스 + 등록소 패턴을 제공하며 5대 카테고리 32개의 감지기를 지원합니다. **구현 완료 (2026-07-29).**

## 패키지 구조

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — 注册所有内置 detector
├── injection/               # 注入类攻击 (10)
├── protocol/                # 协议与请求攻击 (9)
├── httpval/                 # HTTP 协议层校验 (5)
├── data/                    # 数据与序列化攻击 (5)
├── file/                    # 文件与敏感数据 (3)
└── storage/                 # 可插拔存储后端
    ├── storage.go           # Backend interface
    ├── memory.go            # 内存实现 (带 TTL 清理)
    ├── file.go              # JSON 文件持久化
    └── redis/               # Redis 子模块 (可选依赖)
```

## 핵심 API

전체 API 인터페이스(`Result`, `Detector`, `Engine`, 저장 백엔드 `Backend`, HTTP 검증기)는 별도 문서를 참조하세요: **[API 인터페이스 문서](../api.md)**

- 모든 감지기는 사전 컴파일된 정규식 패턴을 사용합니다

## 감지기

| 카테고리 | 이름 | 핵심 패턴 |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS vectors |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, boolean blind, schema enum |
| injection | command | backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass |
| injection | ldap | filter operators `(`, `)`, `&`, `|`, `*` |
| injection | xpath | boolean bypass `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, deep nested query, mutation detect |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO |
| protocol | ssrf | internal IP, 169.254.169.254, IPv6 loopback, gopher/dict |
| protocol | xxe | `<!ENTITY`, parameter entities, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, Set-Cookie/Location injection |
| protocol | host_header | CRLF Host injection, X-Forwarded-Host poisoning |
| protocol | request_smuggling | TE/CL mismatch, dual TE, folded header |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, ACA* header injection |
| protocol | websocket | Upgrade injection, null Origin, ws:// |
| protocol | dns_rebinding | Host header internal IP, localhost, hostname without TLD |
| httpval | method | Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Max size check → 413 (default 10MB) |
| httpval | content_type | MIME whitelist → 415 |
| httpval | csrf_origin | Cross-origin Origin vs Host match |
| httpval | ip_blacklist | Window-based rate limit → auto ban (5/60s → 15min) |
| data | deserialization | PHP `O:数字:`, `C:数字:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |

## 비목표 (Non-Goals)

- HTTP 미들웨어 없음 (순수 탐지 라이브러리)
- 실시간 요청 차단 없음 (호출자가 탐지를 호출)
- 공격 차단 없음 (탐지만 수행; ip_blacklist는 차단 지원 제공)

## 구현 상태 (2026-07-29)

- **32개 감지기 전부 구현** — 등록 진입점 `all.RegisterAll(engine)`
- **테스트 커버리지** — 7/8 패키지에 테스트 있음(`all` 패키지 보완 예정), httpval에 32개 테스트 추가 작성
- **코드 리뷰 완료** — 3개 Bug 수정(리뷰 보고서 참조), `go vet` 경고 0건
- **알려진 제한사항** — `storage/redis/` 서브모듈에 `go mod tidy` 필요; protocol 패키지 receiver 스타일 통일 예정
- **보고서** — [코드 리뷰 보고서](../reports/2026-07-29-code-review-report.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
