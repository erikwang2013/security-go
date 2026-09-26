# Attack Detection Package — Design Spec

## Overview

纯 Go 攻击检测库，提供统一接口 + 注册表模式，覆盖 6 大类 36 个检测器。**实现完成 (2026-07-29)；`session` 包于 2026-09-15 追加。**

## Package Structure

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

## Core API

完整 API 接口（`Result`、`Detector`、`Engine`、存储后端 `Backend`、HTTP 校验器）见独立文档：**[API 接口文档](../../api.md)**

- All detectors use pre-compiled regex patterns

## Detectors

| Category | Name | Key Patterns |
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
| session | session_guard | token↔client binding: UA/fingerprint change (client hijack), IP subnet/country change (remote login), login-network history; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
| session | data_tamper | HMAC-SHA256 over canonical params, ±5m timestamp window, nonce replay counter |

## Non-Goals

- No general-purpose HTTP middleware — the only exception is `session.Tracker.Guard`, a thin wrapper that answers 401 when `Check` detects
- No real-time request interception (caller invokes detection)
- No attack blocking (detection only; ip_blacklist provides block-listing support)

## Implementation Status (2026-07-29)

- **32 detector 全部实现** — 注册入口 `all.RegisterAll(engine)`
- **测试覆盖** — 7/8 包有测试（`all` 包待补），httpval 已补写 32 个测试
- **代码审查完成** — 修复 3 个 Bug（见审查报告），`go vet` 零警告
- **已知限制** — `storage/redis/` 子模块需 `go mod tidy`；protocol 包 receiver 风格待统一
- **报告** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

## Addendum — session 包 (2026-09-15)

会话安全作为第 6 类追加，设计约束与上文一致：

- **`session.Tracker`** (`session_guard`) — `Issue` 绑定 token → IP 网段 / UA / 设备指纹；`Check` 逐请求比对，命中 `client_hijack`（UA 或指纹变化，Critical）或 `remote_login`（跨国家 Critical / 跨网段 High）；`Guard` 命中即 401；`Observe` 在登录时比对该用户历史网段；`Revoke` 立即失效。
- **`session.Signer`** (`data_tamper`) — 参数 HMAC-SHA256 签名 `<时间戳>.<nonce>.<签名>`，校验顺序为时间戳 → 签名 → nonce 计数，因此伪造签名无法消耗合法 nonce。重放计数复用 `storage.Backend`。
- **暴力破解防护** — `RecordFailure(identity, r)` 记录登录失败，跨阈值即锁定，每次翻倍至 `MaxLockout`（默认 24h）；`CheckLogin` 另按客户端 IP 统计失败过的不同身份，达 `StuffingLimit`（默认 10）报 `credential_stuffing`；`GuardLogin` 为登录端点中间件，命中返回 429 + `Retry-After`。渐进退避是为了不让「锁死任意账号」本身成为 DoS 手段。
- **存储** — 会话结构无法用只支持计数/封禁的 `storage.Backend` 表达，故新增 `session.Store`（`Save` / `Load` / `Delete`）+ `MemoryStore`；`storage.Backend` 与其三个实现均未改动。
- **不注册进 `Engine`** — `Detector.Detect(input string)` 取不到 token / 客户端 IP / UA，故 `Tracker` 直接接收 `*http.Request`；`all.RegisterAll` 保持只注册零配置检测器。
- **测试** — `session` 包 5 个测试文件（store / tracker / tamper / lockout / bruteforce），`go test ./... -race` 通过。

## Addendum — pet 包与文档资产 (2026-09-26)

- **`pet` 包** — 项目宠物哨兵鼠（Sentinel Gopher）作为构建期资产入库：`pet.SVG() []byte`、`pet.Handler() http.Handler`、`pet.Banner() string`。`go:embed` 内嵌 `pet/pet.svg`，运行时无文件依赖，也未新增任何第三方依赖，核心库零依赖性质不变。`Banner()` 为启动横幅纯文本（含尾部换行）；`SVG()` 返回共享切片，调用方不得修改。
- **`Handler` 走 `http.ServeContent`，不用裸 `w.Write`** — `pet.svg` 约 6 KB，超过 net/http 的 2 KiB 响应嗅探缓冲，裸 `Write` 会退化为 chunked 且无 `Content-Length`；`ServeContent` 顺带获得 `Range` 与正确的 `HEAD`。响应头为 `image/svg+xml; charset=utf-8` + `Cache-Control: public, max-age=86400`，无副作用，适合挂在诊断 / 调试路由上。
- **文档配图** — 三张手写 SVG（架构 / 功能 / 生命周期），由源码生成而非 Mermaid 绘制，各含中英两版：`docs/images/{architecture,features,lifecycle}[-en].svg`。英文版只替换文本节点，几何与中文原版逐字节一致（已核对非文本行完全相同）；两份英文 README 引用 `-en` 一套，其余语言 README 共用中文一套。
- **36 与 34 是两个数，勿「统一」** — 36 是项目检测器总数（27 个零配置 + 7 个 httpval + 2 个 session），写在吉祥物盾牌、`pet.Banner`、两份 README 与 12 份译文里；34 是满足 `security.Detector`、可经 `Engine` 调度的那部分（`all.RegisterAll` 自动注册的 27 个 + 需应用自行注册的 7 个 httpval）。`session.Tracker` 与 `session.Signer` 只有 `Name()`、没有 `Detect(string)`，故不计入 34。两个数各自成立，且均已出现在图中（`architecture.svg`「34 个经 Engine 调度」、`lifecycle.svg`「遍历注册表 34 个检测器」）。
- **计数由一处测试钉住** — `all/all_test.go:TestTotalDetectorCountIs36` 是唯一把 36 绑回代码的地方：增删检测器必须让它失败，其报错信息指向 `pet/pet.svg`、`pet.Banner` 与各 README。
- **宠物由检测结果驱动（情绪 API）** — `pet.MoodOf([]*security.Result) Mood` 把一次扫描分为三态：无命中 `Calm`、有命中但无 High/Critical `Watchful`、至少一个 High 或 Critical `Alarmed`；`pet.SVGFor(Mood)` 返回对应形态（`pet/mood-{watchful,alarmed}.svg`，由 `pet.svg` 按定点替换生成，几何除刻意改动外与基图一致），未知取值回退 `Calm`；`pet.MoodHandler(func(*http.Request) Mood) http.Handler` 以 `Cache-Control: no-store` 提供实时状态——与静态的 `Handler` 不同，其输出随扫描变化，缓存一天会返回过期形态。
- **`MoodOf` 只统计 `Detected` 为真的结果** — 检测器在未命中时也会填 `Severity`，仅凭严重度字段会把干净流量判成告警。命中越严重优先级越高，与结果顺序无关。该约束由 `pet/mood_test.go` 固化，并已证伪（去掉 `!r.Detected` 判断即失败）。
- **`pet` 是叶子包** — 只依赖根 `security` 包取 `Result`/`Severity`，核心库不反向依赖它，无环；未接入 `Engine`，状态由调用方组合（`MoodOf(e.DetectRequest(r))`），核心库不持有统计状态。

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
