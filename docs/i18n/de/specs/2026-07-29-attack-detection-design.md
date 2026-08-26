# Paket zur Angriffserkennung — Design-Spezifikation

## Übersicht

Eine reine Go-Bibliothek zur Angriffserkennung mit einheitlicher Schnittstelle + Registry-Muster, die 32 Detektoren in 5 Kategorien abdeckt. **Implementierung abgeschlossen (2026-07-29).**

## Paketstruktur

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

## Kern-API

Die vollständigen API-Schnittstellen (`Result`, `Detector`, `Engine`, Storage-Backend `Backend`, HTTP-Validator) finden Sie im separaten Dokument: **[API-Referenz](../api.md)**

- Alle Detektoren verwenden vorkompilierte Regex-Muster

## Detektoren

| Kategorie | Name | Wichtige Muster |
|-----------|------|-----------------|
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

## Nicht-Ziele

- Kein HTTP-Middleware (reine Erkennungsbibliothek)
- Keine Echtzeit-Anfrageabfangung (der Aufrufer führt die Erkennung aus)
- Keine Angriffsblockierung (nur Erkennung; ip_blacklist bietet Unterstützung für Sperrlisten)

## Implementierungsstatus (2026-07-29)

- **Alle 32 Detektoren implementiert** — Registrierungseinstieg `all.RegisterAll(engine)`
- **Testabdeckung** — 7/8 Pakete haben Tests (Paket `all` fehlt noch), für httpval wurden 32 Tests ergänzt
- **Code-Review abgeschlossen** — 3 Bugs behoben (siehe Review-Bericht), `go vet` ohne Warnungen
- **Bekannte Einschränkungen** — Untermodul `storage/redis/` benötigt `go mod tidy`; der Receiver-Stil im protocol-Paket muss noch vereinheitlicht werden
- **Bericht** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
