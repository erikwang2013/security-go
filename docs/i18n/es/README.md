# Security Go — biblioteca de detección de ataques

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Documentación de la API](api.md)

Paquete de detección de ataques escrito en Go que cubre **32 detectores**, **5 categorías principales de ataques** y **3 backends de almacenamiento conectables**. Interfaz unificada + patrón de registro (registry), biblioteca de detección pura, adaptable a cualquier framework HTTP de Go.

## Enfoque de diseño

### Principios principales

- **Detección de cero dependencias** — todos los detectores usan únicamente el `regexp` de la biblioteca estándar de Go, sin dependencias externas
- **Interfaz unificada** — cada detector implementa la interfaz `Detector` (`Name()` + `Detect()`), gestionada de forma unificada a través del registro `Engine`
- **Expresiones regulares precompiladas** — todos los patrones se compilan en la inicialización de `var`, con cero sobrecarga en tiempo de ejecución
- **Configuración bajo demanda** — los detectores de inyección/protocolo/datos/archivos son plug-and-play; los validadores HTTP requieren configuración personalizada

### Arquitectura de diseño

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

### Flujo de datos

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

### Niveles de severidad

| Nivel | Descripción | Escenario típico |
|------|------|---------|
| `SeverityLow` | Bajo riesgo | Método HTTP no permitido, discrepancia de Content-Type |
| `SeverityMedium` | Riesgo medio | Problemas de configuración CORS, redirección abierta, introspección GraphQL |
| `SeverityHigh` | Alto riesgo | XSS, inyección SQL, SSRF, path traversal |
| `SeverityCritical` | Crítico | Inyección de comandos, JNDI, SSTI, XXE, fuga de datos |

## Funcionalidades implementadas

### Ataques de inyección (10)

| Detector | Patrones de detección |
|--------|---------|
| **XSS** | `<script>`, manejadores de eventos `on[a-z]+=`, pseudo-protocolo `javascript:`, inyección SVG/CSS, `eval()`, `document.cookie` |
| **Inyección SQL** | `UNION SELECT` (incluido el bypass con `/**/`), `sleep/benchmark/pg_sleep`, inyección booleana ciega, enumeración de `information_schema`, `xp_cmdshell` |
| **Inyección de comandos** | backticks, `$()`, operador pipe, `/dev/tcp`, PHP `system/exec/shell_exec`, ejecución encadenada `&&` `;` `\|\|` |
| **Inyección NoSQL** | Operadores de MongoDB `$ne` `$gt` `$regex` `$where`, `$func`, inyección de claves JSON |
| **Inyección LDAP** | Operadores de filtro `(\|(&(!`, `objectClass=*`, bypass por codificación URL |
| **Inyección XPATH** | Bypass booleano `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, ofuscación `${lower:j}`, variables de entorno `${env:}`, protocolos `ldap/rmi/dns` |
| **Inyección SSI** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **Inyección GraphQL** | Introspección `__schema`/`__type`, DoS por anidamiento profundo (5+ niveles), detección de `mutation` |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, recorrido de MRO de Python, acceso a `config/self` |

### Ataques de protocolo y de petición (9)

| Detector | Patrones de detección |
|--------|---------|
| **SSRF** | IPs internas (127/10/172.16/192.168), `169.254.169.254`, loopback IPv6, protocolos `gopher/dict/file/ftp` |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, entidades de parámetro `%entity;`, declaración DOCTYPE |
| **Inyección de cabeceras HTTP** | CRLF `%0d%0a` / `\r\n`, inyección de Set-Cookie/Location/Content-Length |
| **Ataque de cabecera Host** | Inyección CRLF en Host, envenenamiento de `X-Forwarded-Host`, `X-Original-URL` |
| **Request smuggling** | Inconsistencia Transfer-Encoding/Content-Length, doble cabecera TE, ofuscación con cabeceras plegadas `\x0b` |
| **Redirección abierta** | URL relativa de protocolo `//evil.com`, pseudo-protocolos `javascript:/data:` |
| **Bypass CORS** | `Origin: null`, inyección de cabeceras `Access-Control-Allow-*` |
| **Secuestro de WebSocket** | Inyección de cabecera Upgrade, bypass de Origin null, URLs `ws://` |
| **DNS rebinding** | IP interna en la cabecera Host, localhost, nombre de host corto sin TLD |

### Validación de capa de protocolo HTTP (5)

| Detector | Descripción |
|--------|------|
| **Método HTTP** | Solo permite GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH; los demás devuelven una alerta |
| **Tamaño del cuerpo de la petición** | Alerta cuando se supera el límite (10 MB por defecto) |
| **Content-Type** | Solo permite la lista blanca de tipos MIME configurada |
| **CSRF Origin** | Detecta si el Origin de las peticiones cross-origin coincide con el Host; admite una lista blanca adicional |
| **Lista negra de IPs** | Bloqueo automático tras N ataques en la ventana de tiempo (por defecto 5 veces/60s → bloqueo de 15 minutos); admite almacenamiento File/Redis/Memory |

### Ataques de datos y serialización (5)

| Detector | Patrones de detección |
|--------|---------|
| **Deserialización PHP** | Objetos serializados `O:número:` / `C:número:`, `unserialize()`, métodos mágicos (`__wakeup`/`__destruct`) |
| **Inyección CSV** | `=cmd\|`, `@SUM(`, prefijos de fórmula `+`/`-`, `HYPERLINK`/`DDE` |
| **Inyección de cabeceras de correo** | Inyección en Bcc/Cc/From/To, MIME multipart, parámetro boundary |
| **Ataque JWT** | Bypass `alg: none`, path traversal en `kid`, detección de firma vacía (análisis de decodificación estructural) |
| **Prototype pollution** | Claves `__proto__`/`constructor`, `__defineGetter__`/`__defineSetter__` |

### Archivos y datos sensibles (3)

| Detector | Patrones de detección |
|--------|---------|
| **Path traversal** | `../`, `..\\`, `php://filter`/`php://input`, byte null, bypass por codificación URL, `/etc/passwd` |
| **Subida maliciosa** | Lista blanca de extensiones (15) + escaneo de contenido con etiquetas PHP `<?php`/`<?=` |
| **Fuga de datos** | Números de tarjeta de crédito, AWS Access Key, claves privadas `-----BEGIN`, cadenas de conexión a bases de datos, API Token, JWT Secret, GitHub PAT |

### Backends de almacenamiento (3)

| Backend | Descripción |
|------|------|
| **Memory** | `sync.Mutex` + map, limpieza automática de entradas caducadas cada 30s |
| **File** | Persistencia en archivos JSON, flush al llamar a Close |
| **Redis** | Submódulo independiente, Pipeline Incr + TTL, requiere `go-redis/v9` |

## Instrucciones de uso

### Instalación

```bash
go get github.com/erikwang2013/security-go
```

### Inicio rápido

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

### Detección de peticiones HTTP

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

### Configuración de validadores HTTP

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

### Detector personalizado

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

### Documentación relacionada

- [Documentación de la API](api.md) — tipos principales, interfaces Detector/Engine, interfaz del backend de almacenamiento, validadores HTTP
- [Especificación de diseño](specs/2026-07-29-attack-detection-design.md) — estructura de paquetes, catálogo de detectores
- [Plan de implementación](plans/2026-07-29-attack-detection-plan.md) — plan de tareas paso a paso y desviaciones frente a la implementación
- [Informe de revisión de código](reports/2026-07-29-code-review-report.md) — corrección de bugs, cobertura de pruebas, evaluación de la arquitectura

---

## Documentos multilingües

| Idioma | Documento |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

Índice completo: [docs/i18n/README.md](../README.md)

---

## Donaciones

Si este proyecto te resulta útil, ¡agradecemos tu apoyo:

| Método | Código QR |
|------|--------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### Donaciones por transferencia global (transferencia bancaria)

**Información del beneficiario**

- Nombre del beneficiario: WANG KEXUN
- Número de cuenta del beneficiario: 881015918251

**Banco del beneficiario (ZA Bank)**

- SWIFT Code：`AABLHKHHXXX`
- Nombre del banco: ZA Bank Limited
- Código del banco: 387
- Dirección del banco: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Banco intermediario para transferencias transfronterizas (si es necesario)**

> Ten en cuenta que esta es la información del banco intermediario (corresponsal) para transferencias transfronterizas, no la del banco del beneficiario. Consulta con tu banco emisor si es necesario proporcionar los datos del banco intermediario.

- El banco intermediario para remesas en dólares de Hong Kong (HKD), yuanes (CNY) y dólares estadounidenses (USD) es Citibank:
  - Nombre del banco: Citibank N.A. Hong Kong
  - SWIFT Code：`CITIHKHXXXX`
  - Código del banco: 006
  - Nombre de la sucursal: Hong Kong Branch
  - Número de sucursal: 391
  - Dirección del banco: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- Para otras monedas, el banco intermediario es BNY Mellon:
  - Nombre del banco: THE BANK OF NEW YORK MELLON
  - SWIFT Code：`IRVTUS3NXXX`
  - Dirección del banco: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

See [README-EN.md](../../../README-EN.md) for the full English documentation.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
