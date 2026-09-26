# Security Go — biblioteca de detección de ataques

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Documentación de la API](api.md)

Paquete de detección de ataques escrito en Go que cubre **36 detectores**, **6 categorías principales de ataques** y **3 backends de almacenamiento conectables**. Interfaz unificada + patrón de registro (registry), biblioteca de detección pura, adaptable a cualquier framework HTTP de Go.

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>Mascota del proyecto <b>Sentinel Gopher</b> (哨兵鼠) — un gopher de Go montando guardia con un escudo.<br>El <b>36</b> del escudo es el número de detectores; la lupa representa el escaneo en cada petición.</sub>
</p>

[Arquitectura](#arquitectura-de-diseño) · [Funcionalidades](#funcionalidades-implementadas) · [Ciclo de vida](#ciclo-de-vida) · [Estructura del proyecto](#estructura-del-proyecto) · [La mascota](#la-mascota)

## Enfoque de diseño

### Principios principales

- **Detección de cero dependencias** — todos los detectores usan únicamente el `regexp` de la biblioteca estándar de Go, sin dependencias externas
- **Interfaz unificada** — cada detector implementa la interfaz `Detector` (`Name()` + `Detect()`), gestionada de forma unificada a través del registro `Engine`
- **Expresiones regulares precompiladas** — todos los patrones se compilan en la inicialización de `var`, con cero sobrecarga en tiempo de ejecución
- **Configuración bajo demanda** — los detectores de inyección/protocolo/datos/archivos son plug-and-play; los validadores HTTP y la detección de seguridad de sesión requieren configuración personalizada de la aplicación

### Arquitectura de diseño

![Arquitectura](../../../docs/images/architecture.svg)

> El paquete `session` no se registra en la `Engine`: la validación de sesión necesita leer el `*http.Request` completo (token, IP del cliente, User-Agent)
> y la aplicación debe aportar el almacenamiento y la clave, por lo que se invoca directamente como middleware; consulta más abajo «Configuración de seguridad de sesión».

### Ciclo de vida

El ciclo completo de una petición, desde la entrada y pasando por la detección hasta el tratamiento graduado (incluido el ciclo de bloqueo de IP y el reescaneo tras decodificar la URL), además del recorrido de una sesión desde el enlace hasta la revocación:

![Ciclo de vida](../../../docs/images/lifecycle.svg)

### Niveles de severidad

| Nivel | Descripción | Escenario típico |
|------|------|---------|
| `SeverityLow` | Bajo riesgo | Método HTTP no permitido, discrepancia de Content-Type |
| `SeverityMedium` | Riesgo medio | Señales débiles: mala configuración de CORS, redirección abierta, introspección GraphQL, más los patrones sin contexto que cada detector separa a propósito (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, acentos graves, `{#…#}`, `__proto__:`, nombres de métodos mágicos de PHP), habituales en tutoriales y contenido normal |
| `SeverityHigh` | Alto riesgo | Señales fuertes: XSS, inyección SQL, SSRF, path traversal, anomalías de sesión |
| `SeverityCritical` | Crítico | Señales fuertes: inyección de comandos, JNDI, SSTI, XXE, fuga de datos, deserialización (objetos serializados PHP / pickle / Java / .NET) |

## Funcionalidades implementadas

### Resumen de funcionalidades

![Diseño de funcionalidades](../../../docs/images/features.svg)

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

### Validación de capa de protocolo HTTP (7)
| **Profundidad de anidamiento JSON** | Escanea en streaming con `json.Decoder`: marca una bomba JSON cuando la profundidad o el número de elementos superan el límite (profundidad por defecto 32). El JSON inválido o truncado nunca alerta |
| **Atributos de Set-Cookie** | Detecta `Set-Cookie` sin `Secure`/`HttpOnly`/`SameSite`, con valor demasiado largo o vacío; los atributos ausentes se agrupan en un solo resultado |

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
| **Deserialización** | Objetos serializados `O:número:` / `C:número:`, `unserialize()`, métodos mágicos (`__wakeup`/`__destruct`); cubre cargas PHP / pickle / Java / .NET |
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

### Seguridad de sesión (2)

| Detector | Patrones de detección |
|--------|---------|
| **Guardián de sesión** (`session_guard`) | Vinculación del token con el cliente en el momento de crear la sesión, comparada en cada petición: un cambio de User-Agent o de huella del dispositivo determina **secuestro del cliente** (Critical); si la IP del cliente cae en otra subred o país determina **inicio de sesión desde otra ubicación** (High/Critical); `Observe()` compara las subredes históricas al iniciar sesión y alerta cuando aparece una nueva subred. La sesión se renueva de forma deslizante y `Revoke()` puede invalidarla de inmediato; `RecordFailure()` cuenta los intentos fallidos y bloquea el token al alcanzar el umbral dentro de la ventana, `Check()` pasa a informar `token_locked` y `ClearFailures()` pone el contador a cero tras un inicio de sesión correcto; `CheckLogin()` además detecta credential stuffing (un cliente que falla contra demasiadas identidades distintas reporta `credential_stuffing`), y el bloqueo se duplica en cada repetición, con tope de 24 h |
| **Manipulación de datos** (`data_tamper`) | Firma HMAC-SHA256 sobre los parámetros de la petición (`marca de tiempo.nonce.firma`), que identifica parámetros modificados, claves que no coinciden, desviación de la marca de tiempo y repetición de firmas (contador de nonce) |

### Backends de almacenamiento (3)

| Backend | Descripción |
|------|------|
| **Memory** | `sync.Mutex` + map, limpieza automática de entradas caducadas cada 30s |
| **File** | Persistencia en archivos JSON, flush al llamar a Close |
| **Redis** | Submódulo independiente, Pipeline Incr + TTL, requiere `go-redis/v9` |

## Estructura del proyecto

```
security-go/
├── security.go            # Núcleo: Result / Severity / interfaz Detector / registro Engine
├── injection/             # Detectores de inyección (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # Detectores de protocolo y de petición (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # Detectores de datos y serialización (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # Detectores de archivos y datos sensibles (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # Validadores de protocolo HTTP (7), cada uno necesita ajustes de la aplicación
├── session/               # Seguridad de sesión (2): session_guard, data_tamper
│                          #   Omite el Engine y se usa directamente como middleware
├── storage/               # Backends de almacenamiento
│   ├── storage.go         #   Interfaz del backend: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map, limpieza en segundo plano cada 30 s
│   ├── file.go            #   File: persistencia JSON, flush al llamar a Close
│   └── redis/             #   Redis: submódulo aparte con su propio go.mod
├── all/                   # Registro en una sola llamada de los 27 detectores sin configuración
├── pet/                   # Mascota del proyecto: SVG embebido + banner de inicio
├── docs/
│   ├── api.md             # Referencia de la API
│   ├── images/            # SVGs de arquitectura / funcionalidades / ciclo de vida
│   ├── i18n/              # Documentación traducida (12 idiomas)
│   └── superpowers/       # Especificación de diseño, plan de implementación, informes de revisión de código
└── tests/                 # Informes de cobertura
```

Cada paquete de detector empareja `xxx.go` con `xxx_test.go`; `all` además incluye pruebas de regresión.

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
    all.RegisterAll(e) // registra los 27 detectores sin configuración de una sola vez

    // Detección individual
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("Detectado: %v, Severidad: %d\n", r.Detected, r.Severity)

    // Detección masiva
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
            log.Printf("Ataque detectado: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### Configuración de validadores HTTP

```go
// Validación del método
e.Register(&httpval.Method{})

// Límite del tamaño del cuerpo de la petición
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Lista blanca de Content-Type
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Comprobación de CSRF Origin
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// Lista negra de IPs (bloqueo automático: 5 ataques/60s → bloqueo de 15 min)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// Registrar el ataque
blocked, _ := bl.RecordAttack(clientIP)
```

### Configuración de seguridad de sesión

El paquete `session` se usa directamente como middleware, sin pasar por `Engine`. El almacenamiento debe aportarlo la aplicación (se ofrece una implementación en memoria por defecto, sustituible por Redis, etc.):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // opcional: conectar GeoIP para detectar inicios de sesión entre países

// Vincular la sesión tras un inicio de sesión correcto (el token lo genera tu flujo de login)
// Detección de inicio de sesión remoto: compara con las subredes históricas del usuario y alerta si aparece una nueva
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // vincula el token → subred IP / UA / huella del dispositivo
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// Proteger rutas: devuelve 401 ante secuestro o inicio de sesión remoto
mux.Handle("/api/", tr.Guard(apiHandler))

// o solo detecta y decide tú mismo la respuesta
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// Cerrar sesión
tr.Revoke(token)
```

Detección de manipulación de datos: el cliente y el servidor comparten una clave, el cliente firma los parámetros y el servidor recalcula la verificación:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // el segundo argumento bloquea la repetición de firmas, puede ser nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // Cliente: envíalo junto con los parámetros

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` está desactivado por defecto: `X-Forwarded-For` / `X-Real-IP` son controlables por el cliente, activa esta opción solo detrás de un proxy inverso propio.
> `FailClosed` está desactivado por defecto (se permite el paso cuando falla el almacenamiento, igual que `IPBlacklist`); se recomienda activarlo en negocios sensibles a la sesión.

### Detector personalizado

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "Contenido malicioso detectado",
    }
}

e.Register(&MyDetector{})
```

### La mascota

El paquete `pet` embebe el Sentinel Gopher como SVG en tiempo de compilación mediante `go:embed` — sin dependencia de archivos en tiempo de ejecución y sin añadir dependencias de terceros:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // banner de inicio: texto plano apto para terminal
http.Handle("/pet.svg", pet.Handler()) // ruta de depuración: se sirve como image/svg+xml, cacheada un día
svg := pet.SVG()                       // o toma los bytes SVG sin procesar
```

### Documentación relacionada

- [Documentación de la API](api.md) — tipos principales, interfaces Detector/Engine, interfaz del backend de almacenamiento, validadores HTTP
- [Especificación de diseño](specs/2026-07-29-attack-detection-design.md) — estructura de paquetes, catálogo de detectores
- [Plan de implementación](plans/2026-07-29-attack-detection-plan.md) — plan de tareas paso a paso y desviaciones frente a la implementación
- [Informe de revisión de código](reports/2026-07-29-code-review-report.md) — corrección de bugs, cobertura de pruebas, evaluación de la arquitectura
- [Informe de revisión de código v2](reports/2026-07-29-code-review-report-v2.md) — Segunda pasada: 4 problemas corregidos, 18 archivos de prueba añadidos

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
