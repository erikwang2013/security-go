# Paquete de detección de ataques — Especificación de diseño

## Visión general

Biblioteca de detección de ataques en Go puro, con interfaz unificada + patrón de registro, que cubre 36 detectores en 6 categorías. **Implementación completada (2026-07-29); el paquete `session` se añadió el 2026-09-15.**

## Estructura de paquetes

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

## API principal

Las API completas (`Result`, `Detector`, `Engine`, `Backend` de almacenamiento, validadores HTTP) se describen en el documento independiente: **[Documentación de la API](../api.md)**

- Todos los detectores usan patrones de expresiones regulares precompilados

## Detectores

| Categoría | Nombre | Patrones clave |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, vectores SVG/CSS |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, inyección booleana ciega, enumeración de esquema |
| injection | command | backtick, `$()`, pipe, `/dev/tcp`, funciones exec de PHP |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, bypass de autenticación |
| injection | ldap | operadores de filtro `(`, `)`, `&`, `|`, `*` |
| injection | xpath | bypass booleano `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, consulta profundamente anidada, detección de mutation |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, MRO de Python |
| protocol | ssrf | IP interna, 169.254.169.254, loopback IPv6, gopher/dict |
| protocol | xxe | `<!ENTITY`, entidades de parámetro, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, inyección en Set-Cookie/Location |
| protocol | host_header | Inyección CRLF en Host, envenenamiento de X-Forwarded-Host |
| protocol | request_smuggling | Discrepancia TE/CL, doble TE, cabecera plegada |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, inyección de cabeceras ACA* |
| protocol | websocket | Inyección de Upgrade, Origin null, ws:// |
| protocol | dns_rebinding | IP interna en cabecera Host, localhost, hostname sin TLD |
| httpval | method | Lista blanca GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Comprobación de tamaño máximo → 413 (10MB por defecto) |
| httpval | content_type | Lista blanca MIME → 415 |
| httpval | csrf_origin | Coincidencia de Origin vs Host en peticiones cross-origin |
| httpval | ip_blacklist | Límite de tasa por ventana → bloqueo automático (5/60s → 15min) |
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:número:`, `C:número:`, unserialize() |
| data | csv_injection | prefijos de fórmula `=`, `@`, `+`, `-` |
| data | mail_header | Inyección en Bcc/Cc/From/To, MIME |
| data | jwt_attack | alg:none, path traversal en kid, firma vacía |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, byte null |
| file | upload | Lista blanca de extensiones + escaneo de contenido con etiquetas PHP |
| file | data_leak | Tarjeta de crédito, AWS key, clave privada, cadena de conexión, JWT secret |
| session | session_guard | Vinculación token↔cliente: cambio de UA/huella (secuestro del cliente), cambio de subred o país de la IP (inicio de sesión desde otra ubicación), historial de redes de inicio de sesión; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
| session | data_tamper | HMAC-SHA256 sobre parámetros canónicos, ventana de marca de tiempo de ±5m, contador de nonce contra repetición |

## Objetivos no incluidos (Non-Goals)

- Sin middleware HTTP de propósito general — la única excepción es `session.Tracker.Guard`, un envoltorio fino que devuelve 401 cuando `Check` detecta
- Sin interceptación de peticiones en tiempo real (el llamador invoca la detección)
- Sin bloqueo de ataques (solo detección; ip_blacklist ofrece soporte de bloqueo)

## Estado de la implementación (2026-07-29)

- **Los 32 detectores están implementados** — punto de registro `all.RegisterAll(engine)`
- **Cobertura de pruebas** — 7/8 paquetes tienen pruebas (falta el paquete `all`), httpval ha añadido 32 pruebas
- **Revisión de código completada** — se corrigieron 3 bugs (ver el informe de revisión), `go vet` sin advertencias
- **Limitaciones conocidas** — el submódulo `storage/redis/` requiere `go mod tidy`; el estilo de receivers del paquete protocol está pendiente de unificar
- **Informe** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

## Apéndice — paquete `session` (2026-09-15)

La seguridad de sesión se añadió como 6.ª categoría, con las mismas restricciones de diseño descritas arriba:

- **`session.Tracker`** (`session_guard`) — `Issue` vincula token → subred IP / UA / huella del dispositivo; `Check` compara en cada petición y detecta `client_hijack` (cambio de UA o de huella, Critical) o `remote_login` (cambio de país Critical / cambio de subred High); `Guard` devuelve 401 al detectar; `Observe` compara al iniciar sesión las subredes históricas de ese usuario; `Revoke` invalida de inmediato.
- **`session.Signer`** (`data_tamper`) — firma HMAC-SHA256 de los parámetros `<marca de tiempo>.<nonce>.<firma>`; el orden de verificación es marca de tiempo → firma → contador de nonce, así que una firma falsificada no puede consumir un nonce legítimo. El contador de repetición reutiliza `storage.Backend`.
- **Protección contra fuerza bruta** — `RecordFailure(identity, r)` cuenta los fallos de inicio de sesión y bloquea al alcanzar el umbral, duplicándose cada vez hasta `MaxLockout` (por defecto 24 h); `CheckLogin` cuenta además las identidades distintas por IP de cliente e informa `credential_stuffing` al llegar a `StuffingLimit` (por defecto 10); `GuardLogin` es el middleware del endpoint de autenticación y responde 429 con `Retry-After`. El backoff progresivo evita que bloquear una cuenta arbitraria sea en sí mismo un vector de DoS.
- **Almacenamiento** — La estructura de sesión no puede expresarse con `storage.Backend`, que solo admite conteo/bloqueo, por lo que se añadió `session.Store` (`Save` / `Load` / `Delete`) + `MemoryStore`; `storage.Backend` y sus tres implementaciones no se modificaron.
- **No se registra en la `Engine`** — `Detector.Detect(input string)` no puede acceder al token / la IP del cliente / el UA, por lo que `Tracker` recibe directamente `*http.Request`; `all.RegisterAll` sigue registrando solo los detectores de configuración cero.
- **Pruebas** — 5 archivos de prueba en el paquete `session` (store / tracker / tamper / lockout / bruteforce), `go test ./... -race` correcto.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
