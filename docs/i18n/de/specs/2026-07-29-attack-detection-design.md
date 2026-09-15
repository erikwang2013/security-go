# Paket zur Angriffserkennung — Design-Spezifikation

## Übersicht

Eine reine Go-Bibliothek zur Angriffserkennung mit einheitlicher Schnittstelle + Registry-Muster, die 36 Detektoren in 6 Kategorien abdeckt. **Implementierung abgeschlossen (2026-07-29); das Paket `session` wurde am 2026-09-15 ergänzt.**

## Paketstruktur

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
│   ├── lockout.go           # 失败计数、锁定查找与键
│   ├── bruteforce.go        # 渐进退避 / 撞库检测 / GuardLogin
│   └── tamper.go            # Signer — 篡改数据
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
| session | session_guard | token↔Client-Bindung: Änderung von UA/Fingerabdruck (Client-Entführung), Wechsel von IP-Subnetz/Land (Anmeldung von einem anderen Ort), Historie der Anmeldenetze; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
| session | data_tamper | HMAC-SHA256 über kanonische Parameter, ±5m Zeitstempel-Fenster, Nonce-Zähler gegen Replay |

## Nicht-Ziele

- Keine Allzweck-HTTP-Middleware — die einzige Ausnahme ist `session.Tracker.Guard`, ein dünner Wrapper, der 401 zurückgibt, wenn `Check` anschlägt
- Keine Echtzeit-Anfrageabfangung (der Aufrufer führt die Erkennung aus)
- Keine Angriffsblockierung (nur Erkennung; ip_blacklist bietet Unterstützung für Sperrlisten)

## Implementierungsstatus (2026-07-29)

- **Alle 32 Detektoren implementiert** — Registrierungseinstieg `all.RegisterAll(engine)`
- **Testabdeckung** — 7/8 Pakete haben Tests (Paket `all` fehlt noch), für httpval wurden 32 Tests ergänzt
- **Code-Review abgeschlossen** — 3 Bugs behoben (siehe Review-Bericht), `go vet` ohne Warnungen
- **Bekannte Einschränkungen** — Untermodul `storage/redis/` benötigt `go mod tidy`; der Receiver-Stil im protocol-Paket muss noch vereinheitlicht werden
- **Bericht** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

## Addendum — Paket `session` (2026-09-15)

Die Sitzungssicherheit wurde als 6. Kategorie ergänzt; die Designvorgaben entsprechen dem oben Gesagten:

- **`session.Tracker`** (`session_guard`) — `Issue` bindet token → IP-Subnetz / UA / Gerätefingerabdruck; `Check` vergleicht bei jeder Anfrage und schlägt an mit `client_hijack` (Änderung von UA oder Fingerabdruck, Critical) oder `remote_login` (Länderwechsel Critical / Subnetzwechsel High); `Guard` gibt bei Treffer 401 zurück; `Observe` vergleicht bei der Anmeldung die historischen Subnetze des Benutzers; `Revoke` macht die Sitzung sofort ungültig.
- **`session.Signer`** (`data_tamper`) — HMAC-SHA256-Signatur der Parameter `<Zeitstempel>.<nonce>.<Signatur>`; die Prüfreihenfolge ist Zeitstempel → Signatur → Nonce-Zähler, daher kann eine gefälschte Signatur keine gültige Nonce verbrauchen. Der Replay-Zähler nutzt `storage.Backend` erneut.
- **Brute-Force-Schutz** — `RecordFailure(identity, r)` zählt Anmeldefehler und sperrt bei Erreichen der Schwelle, wobei sich jede Sperre bis `MaxLockout` (Standard 24 h) verdoppelt; `CheckLogin` zählt zusätzlich die verschiedenen Identitäten je Client-IP und meldet `credential_stuffing` bei `StuffingLimit` (Standard 10); `GuardLogin` ist die Middleware des Authentifizierungs-Endpunkts und antwortet mit 429 plus `Retry-After`. Der progressive Backoff verhindert, dass das Sperren eines beliebigen Kontos selbst zum DoS-Vektor wird.
- **Speicher** — Die Sitzungsstruktur lässt sich nicht mit dem nur zählenden/sperrenden `storage.Backend` ausdrücken, daher wurden `session.Store` (`Save` / `Load` / `Delete`) + `MemoryStore` ergänzt; `storage.Backend` und seine drei Implementierungen bleiben unverändert.
- **Keine Registrierung in der `Engine`** — `Detector.Detect(input string)` erreicht token / Client-IP / UA nicht, daher nimmt `Tracker` direkt `*http.Request` entgegen; `all.RegisterAll` registriert weiterhin nur die zero-config-Detektoren.
- **Tests** — 5 Testdateien im Paket `session` (store / tracker / tamper / lockout / bruteforce), `go test ./... -race` erfolgreich.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
