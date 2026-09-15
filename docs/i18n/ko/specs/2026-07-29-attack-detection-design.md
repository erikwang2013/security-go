# Attack Detection 패키지 — 설계 규격

## 개요

순수 Go 공격 탐지 라이브러리로, 통합 인터페이스 + 등록소 패턴을 제공하며 6대 카테고리 36개의 감지기를 지원합니다. **구현 완료 (2026-07-29); `session` 패키지는 2026-09-15에 추가되었습니다.**

## 패키지 구조

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — 注册所有内置 detector
├── injection/               # 注入类攻击 (10)
├── protocol/                # 协议与请求攻击 (9)
├── httpval/                 # HTTP 协议层校验 (7)
├── data/                    # 数据与序列化攻击 (5)
├── file/                    # 文件与敏感数据 (3)
├── session/                 # 会话安全 (2) — 不经过 Engine
│   ├── store.go             # Store interface + MemoryStore
│   ├── tracker.go           # Tracker — 客户端被劫持 / 异地登录
│   └── tamper.go            # Signer — 篡改数据
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
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:数字:`, `C:数字:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |
| session | session_guard | token↔client binding: UA/fingerprint change (client hijack), IP subnet/country change (remote login), login-network history |
| session | data_tamper | HMAC-SHA256 over canonical params, ±5m timestamp window, nonce replay counter |

## 비목표 (Non-Goals)

- HTTP 미들웨어 없음 (순수 탐지 라이브러리) — 단 하나의 예외는 `session.Tracker.Guard`로, `Check`가 탐지하면 401을 반환하는 얇은 래퍼입니다
- 실시간 요청 차단 없음 (호출자가 탐지를 호출)
- 공격 차단 없음 (탐지만 수행; ip_blacklist는 차단 지원 제공)

## 구현 상태 (2026-07-29)

- **32개 감지기 전부 구현** — 등록 진입점 `all.RegisterAll(engine)`
- **테스트 커버리지** — 7/8 패키지에 테스트 있음(`all` 패키지 보완 예정), httpval에 32개 테스트 추가 작성
- **코드 리뷰 완료** — 3개 Bug 수정(리뷰 보고서 참조), `go vet` 경고 0건
- **알려진 제한사항** — `storage/redis/` 서브모듈에 `go mod tidy` 필요; protocol 패키지 receiver 스타일 통일 예정
- **보고서** — [코드 리뷰 보고서](../reports/2026-07-29-code-review-report.md)

## Addendum — session 패키지 (2026-09-15)

세션 보안은 6번째 카테고리로 추가되었으며, 설계 제약은 위와 동일합니다:

- **`session.Tracker`** (`session_guard`) — `Issue`가 token → IP 대역 / UA / 기기 지문을 바인딩; `Check`가 매 요청마다 비교하여 `client_hijack`(UA 또는 지문 변경, Critical) 또는 `remote_login`(국가 간 Critical / 대역 간 High)을 반환; `Guard`는 적중 시 401; `Observe`는 로그인 시 해당 사용자의 과거 대역과 비교; `Revoke`는 즉시 무효화합니다.
- **`session.Signer`** (`data_tamper`) — 파라미터 HMAC-SHA256 서명 `<타임스탬프>.<nonce>.<서명>`, 검증 순서는 타임스탬프 → 서명 → nonce 카운트이므로 위조 서명은 유효한 nonce를 소모할 수 없습니다. 재전송 카운트는 `storage.Backend`를 재사용합니다.
- **저장** — 세션 구조는 카운트/차단만 지원하는 `storage.Backend`로 표현할 수 없어 `session.Store`(`Save` / `Load` / `Delete`) + `MemoryStore`를 새로 추가했습니다; `storage.Backend`와 그 세 구현은 변경되지 않았습니다.
- **`Engine` 미등록** — `Detector.Detect(input string)`은 token / 클라이언트 IP / UA를 얻을 수 없으므로 `Tracker`가 `*http.Request`를 직접 받습니다; `all.RegisterAll`은 제로 구성 감지기만 등록하는 상태를 유지합니다.
- **테스트** — `session` 패키지 테스트 파일 3개(store / tracker / tamper), `go test ./... -race` 통과.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
