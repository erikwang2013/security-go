# Paquete de detección de ataques — Plan de implementación

> **Para trabajadores agénticos:** SUB-HABILIDAD REQUERIDA: usa superpowers:subagent-driven-development (recomendado) o superpowers:executing-plans para implementar este plan tarea por tarea.

**Objetivo:** crear una biblioteca de detección de ataques en Go puro con 32 detectores en 5 categorías, 3 backends de almacenamiento conectables y un registro Engine unificado. **Estado: Completado (2026-07-29).**

**Arquitectura:** diseño de interfaz plana: cada detector implementa `Detector` (Name + Detect). Patrones de expresiones regulares precompilados. Engine proporciona el registro, la búsqueda por nombre y `DetectRequest` para el escaneo completo de peticiones HTTP. RegisterAll vive en `all/all.go` (paquete separado).

**Stack tecnológico:** Go 1.21+, `regexp` de la biblioteca estándar + `net/http`, `go-redis` para el backend Redis (submódulo opcional en `storage/redis/`).

---

### Tarea 1: Inicializar el módulo Go y los tipos principales

**Archivos:**
- Crear: `go.mod`
- Crear: `security.go`

- [x] **Paso 1: Inicializar el módulo Go**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **Paso 2: Crear security.go — Result, Severity, Detector interface, Engine**

```go
package security

import "net/http"

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type Result struct {
	Name     string
	Detected bool
	Message  string
	Severity Severity
	Details  map[string]interface{}
}

type Detector interface {
	Name() string
	Detect(input string) *Result
}

type Engine struct {
	detectors map[string]Detector
}

func NewEngine() *Engine {
	return &Engine{detectors: make(map[string]Detector)}
}

func (e *Engine) Register(d Detector) {
	e.detectors[d.Name()] = d
}

func (e *Engine) Detect(name, input string) *Result {
	if d, ok := e.detectors[name]; ok {
		return d.Detect(input)
	}
	return nil
}

func (e *Engine) DetectAll(input string) []*Result {
	var results []*Result
	for _, d := range e.detectors {
		if r := d.Detect(input); r != nil && r.Detected {
			results = append(results, r)
		}
	}
	return results
}

func (e *Engine) DetectRequest(r *http.Request) []*Result {
	var results []*Result
	inputs := collectRequestInputs(r)
	for _, input := range inputs {
		results = append(results, e.DetectAll(input)...)
	}
	return results
}

func collectRequestInputs(r *http.Request) []string {
	var inputs []string
	inputs = append(inputs, r.URL.String())
	inputs = append(inputs, r.URL.Query().Encode())
	for key, vals := range r.Header {
		for _, v := range vals {
			inputs = append(inputs, key+": "+v)
		}
	}
	for _, c := range r.Cookies() {
		inputs = append(inputs, c.Name+"="+c.Value)
	}
	return inputs
}
```

- [x] **Paso 3: Compilar** — `go build ./...`
- [x] **Paso 4: Commit** — `feat: initialize Go module with core types and Engine`

---

### Tarea 2: Interfaz del backend de almacenamiento y Memory

**Archivos:**
- Crear: `storage/storage.go`
- Crear: `storage/memory.go`

- [x] **Paso 1: storage/storage.go** — interfaz Backend (Incr, Get, Block, IsBlocked, Close)
- [x] **Paso 2: storage/memory.go** — implementación basada en sync.Map con goroutine de limpieza por TTL
- [x] **Paso 3: Compilar** — `go build ./storage/...`
- [x] **Paso 4: Commit** — `feat: add storage interface and memory backend`

---

### Tarea 3: Almacenamiento File y Redis

**Archivos:**
- Crear: `storage/file.go`
- Crear: `storage/redis.go`
- Modificar: `go.mod` (añadir dependencia go-redis)

- [x] **Paso 1: storage/file.go** — persistencia en archivos JSON con flush diferido
- [x] **Paso 2: storage/redis.go** — backend Redis usando go-redis/v9
- [x] **Paso 3: Compilar** — `go build ./storage/...`
- [x] **Paso 4: Commit** — `feat: add file and redis storage backends`

---

### Tarea 4: Detectores de inyección — XSS, SQL

**Archivos:**
- Crear: `injection/xss.go`
- Crear: `injection/sql.go`

- [x] **Paso 1: injection/xss.go** — patrones `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS
- [x] **Paso 2: injection/sql.go** — UNION SELECT (con bypass de `/**/`), sleep/benchmark, inyección booleana ciega, enumeración de esquema, procedimiento almacenado
- [x] **Paso 3: Compilar** — `go build ./injection/...`
- [x] **Paso 4: Commit** — `feat: add XSS and SQL injection detectors`

---

### Tarea 5: Detectores de inyección — Command, NoSQL, LDAP, XPATH

**Archivos:**
- Crear: `injection/command.go`
- Crear: `injection/nosql.go`
- Crear: `injection/ldap.go`
- Crear: `injection/xpath.go`

- [x] **Paso 1: injection/command.go** — backtick, `$()`, pipe, `/dev/tcp`, funciones exec de PHP
- [x] **Paso 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, bypass de autenticación
- [x] **Paso 3: injection/ldap.go** — operadores de filtro `(`, `)`, `&`, `|`, `*`
- [x] **Paso 4: injection/xpath.go** — bypass booleano, string-length, count
- [x] **Paso 5: Compilar y commit**

---

### Tarea 6: Detectores de inyección — JNDI, SSI, GraphQL, SSTI

**Archivos:**
- Crear: `injection/jndi.go`
- Crear: `injection/ssi.go`
- Crear: `injection/graphql.go`
- Crear: `injection/ssti.go`

- [x] **Paso 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, protocolos rmi/dns
- [x] **Paso 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **Paso 3: injection/graphql.go** — `__schema`, `__type`, consulta profundamente anidada, mutation
- [x] **Paso 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, MRO de Python
- [x] **Paso 5: Compilar y commit**

---

### Tarea 7: Detectores de protocolo — SSRF, XXE, Header Injection

**Archivos:**
- Crear: `protocol/ssrf.go`
- Crear: `protocol/xxe.go`
- Crear: `protocol/header_injection.go`

- [x] **Paso 1: protocol/ssrf.go** — IP interna, 169.254.169.254, loopback IPv6, gopher/dict
- [x] **Paso 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, entidades de parámetro, DOCTYPE
- [x] **Paso 3: protocol/header_injection.go** — CRLF, inyección en Set-Cookie/Location
- [x] **Paso 4: Compilar y commit**

---

### Tarea 8: Detectores de protocolo — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**Archivos:**
- Crear: `protocol/host_header.go`
- Crear: `protocol/request_smuggling.go`
- Crear: `protocol/open_redirect.go`
- Crear: `protocol/cors.go`
- Crear: `protocol/websocket.go`
- Crear: `protocol/dns_rebinding.go`

- [x] **Paso 1: Los 6 detectores de protocolo** — un archivo cada uno, patrones de regex precompilados
- [x] **Paso 2: Compilar y commit**

---

### Tarea 9: Detectores de validación HTTP

**Archivos:**
- Crear: `httpval/method.go`
- Crear: `httpval/body_size.go`
- Crear: `httpval/content_type.go`
- Crear: `httpval/csrf_origin.go`
- Crear: `httpval/ip_blacklist.go`

- [x] **Paso 1: httpval/method.go** — lista blanca GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **Paso 2: httpval/body_size.go** — comprobación de tamaño máximo, 10MB por defecto
- [x] **Paso 3: httpval/content_type.go** — lista blanca MIME
- [x] **Paso 4: httpval/csrf_origin.go** — coincidencia de Origin vs Host en peticiones cross-origin
- [x] **Paso 5: httpval/ip_blacklist.go** — límite de tasa por ventana (5/60s → bloqueo de 15min), usa storage.Backend
- [x] **Paso 6: Compilar y commit**

---

### Tarea 10: Detectores de datos/serialización

**Archivos:**
- Crear: `data/deserialization.go`
- Crear: `data/csv_injection.go`
- Crear: `data/mail_header.go`
- Crear: `data/jwt_attack.go`
- Crear: `data/prototype_pollution.go`

- [x] **Paso 1: data/deserialization.go** — PHP `O:número:`, `C:número:`, unserialize(), métodos mágicos
- [x] **Paso 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, prefijos de fórmula `+`, `-`
- [x] **Paso 3: data/mail_header.go** — inyección en Bcc/Cc/From/To, MIME multipart
- [x] **Paso 4: data/jwt_attack.go** — alg:none, path traversal en kid, firma vacía (decodificación estructural)
- [x] **Paso 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **Paso 6: Compilar y commit**

---

### Tarea 11: Detectores de archivos y datos sensibles

**Archivos:**
- Crear: `file/path_traversal.go`
- Crear: `file/upload.go`
- Crear: `file/data_leak.go`

- [x] **Paso 1: file/path_traversal.go** — `../`, `..\\`, php://filter, byte null, bypass por codificación URL
- [x] **Paso 2: file/upload.go** — lista blanca de extensiones + escaneo de contenido con etiquetas PHP
- [x] **Paso 3: file/data_leak.go** — tarjeta de crédito, AWS key, clave privada, cadena de conexión a BD, API token, JWT secret
- [x] **Paso 4: Compilar y commit**

---

### Tarea 12: Integración con Engine — RegisterAll

**Archivos:**
- Modificar: `security.go`

- [x] **Paso 1: Añadir RegisterAll()** — registra los 32 detectores integrados
- [x] **Paso 2: Compilar** — `go build ./...`
- [x] **Paso 3: Commit** — `feat: add RegisterAll for built-in detectors`

---

### Tarea 13: Pruebas

**Archivos:**
- Crear: `security_test.go`
- Crear: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Crear: `protocol/ssrf_test.go`
- Crear: `file/path_traversal_test.go`, `data_leak_test.go`
- Crear: `data/jwt_attack_test.go`
- Crear: `storage/memory_test.go`

- [x] **Paso 1: Escribir las pruebas** — cada una con casos positivos y negativos
- [x] **Paso 2: Ejecutar** — `go test ./... -v`
- [x] **Paso 3: Commit** — `test: add core engine and detector tests`

---

### Tarea 14: Revisión de código posterior a la implementación y correcciones (2026-07-29)

- [x] **Revisión integral del código** — 42 archivos fuente Go, 8 paquetes
- [x] **Corrección de bug #1** — `storage/file.go`: el error de serialización JSON se ignoraba silenciosamente → ahora se comprueba el error y se devuelve
- [x] **Corrección de bug #2** — `httpval/content_type.go`: AllowList vacío permitía todos los Content-Type → valor por defecto deny-all
- [x] **Corrección de bug #3** — `protocol/xxe.go`: `&[a-z]+;` coincidía erróneamente con entidades HTML legítimas → se reduce a una lista de protocolos maliciosos conocidos
- [x] **Pruebas de httpval añadidas** — 32 casos de prueba que cubren 5 detectores (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Pruebas completas** — `go test -count=1 ./...` 7/7 paquetes superados, `go vet` sin advertencias

---

## Desviaciones reales frente a lo planificado

| Planificado | Real | Motivo |
|------|------|------|
| RegisterAll en `security.go` | Paquete independiente `all/all.go` | Evitar referencias circulares: httpval depende de storage, pero el resto de detectores no |
| Redis en el go.mod raíz | Submódulo `storage/redis/` | Aislar la dependencia opcional |
| Receivers uniformes de puntero | El paquete protocol usa receivers de valor | ✅ ya se cambiaron todos a receivers de puntero en la revisión v2 |
| Tareas 4-12 Compilar y commit | Sin commits por pasos | Todo el código se implementó de una vez |

## Resumen de cobertura de pruebas

| Paquete | Archivos de prueba | Nº de pruebas |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (ninguno) | 0 |

> El informe completo está disponible en el [informe de revisión de código v2](../reports/2026-07-29-code-review-report-v2.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
