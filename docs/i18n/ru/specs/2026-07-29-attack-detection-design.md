# Пакет обнаружения атак — спецификация дизайна

## Обзор

Чистая библиотека обнаружения атак на Go с единым интерфейсом + паттерном реестра, охватывающая 5 основных категорий и 32 детектора. **Реализация завершена (2026-07-29).**

## Структура пакета

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

## Основной API

Полный перечень API (`Result`, `Detector`, `Engine`, бэкенд хранилища `Backend`, HTTP-валидаторы) см. в отдельном документе: **[Документация API](../api.md)**

- Все детекторы используют предкомпилированные регулярные выражения
- All detectors use pre-compiled regex patterns

## Детекторы

| Категория | Имя | Ключевые шаблоны |
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

## Вне рамок проекта

- Нет HTTP-мидлвара (чистая библиотека обнаружения)
- Нет перехвата запросов в реальном времени (обнаружение вызывает вызывающий код)
- Нет блокировки атак (только обнаружение; ip_blacklist предоставляет поддержку блокировки)

## Статус реализации (2026-07-29)

- **Все 32 детектора реализованы** — точка регистрации `all.RegisterAll(engine)`
- **Покрытие тестами** — тесты есть в 7 из 8 пакетов (пакет `all` ожидает дополнения), для httpval добавлено 32 теста
- **Ревью кода завершено** — исправлено 3 бага (см. отчёт о ревью), `go vet` без предупреждений
- **Известные ограничения** — подмодуль `storage/redis/` требует `go mod tidy`; стиль receiver в пакете protocol ожидает унификации
- **Отчёт** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
