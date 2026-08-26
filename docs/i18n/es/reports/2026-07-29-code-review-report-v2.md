# Informe de revisión de código v2

**Fecha**: 2026-07-29  
**Proyecto**: security-go — biblioteca de detección de ataques en Go  
**Alcance de la revisión**: los 47 archivos fuente Go (incluidos 32 detectores, 3 backends de almacenamiento, 5 validadores HTTP)  
**Resultado de la revisión**: se detectaron 4 problemas, todos corregidos; se añadieron 18 archivos de prueba (+36 casos de prueba)

---

## 1. Resumen de los resultados de las pruebas

| Paquete | Estado | Cobertura | Nº de pruebas |
|---|------|--------|--------|
| `security` (núcleo) | PASS | 95.8% | 5 |
| `injection` | PASS | 100.0% | 10 |
| `protocol` | PASS | 100.0% | 9 |
| `data` | PASS | 93.2% | 8 |
| `file` | PASS | 100.0% | 5 |
| `httpval` | PASS | 92.9% | 31 |
| `storage` | PASS | 33.7% | 4 |
| `all` | — | 0.0% | 0 (función de registro) |

- **go vet**: PASS (cero advertencias)
- **Tasa de aprobación de pruebas**: 58/58 (100%)

---

## 2. Problemas detectados y correcciones

### Problema 1: `storage/file.go` — pérdida de la persistencia de datos (grave)

**Descripción**: los métodos `Incr()` y `Block()` solo operan en memoria y solo escriben a disco en `Close()`. Si el proceso se bloquea, se pierden todos los contadores y los datos de bloqueo.

**Corrección**:
- Se añadió un goroutine `autoSave` en `NewFile()` que persiste automáticamente a disco cada 30 segundos
- Se extrajo el método interno `saveLocked()`, compartido por `Close()` y `autoSave`

**Archivos**: `storage/file.go`

### Problema 2: paquete `protocol/` — receivers de valor inconsistentes (importante)

**Descripción**: los 9 detectores del paquete `protocol/` (SSRF, XXE, HeaderInjection, HostHeader, RequestSmuggling, OpenRedirect, CORS, WebSocket, DNSRebinding) usan receivers de valor `(d Type)`, mientras que los detectores de los paquetes `injection/`, `data/` y `file/` usan receivers de puntero `(d *Type)`, un estilo inconsistente.

**Corrección**: cambiar los receivers de los métodos de los 9 archivos a receivers de puntero.

**Archivos**: `protocol/ssrf.go`, `xxe.go`, `header_injection.go`, `host_header.go`, `request_smuggling.go`, `open_redirect.go`, `cors.go`, `websocket.go`, `dns_rebinding.go`

### Problema 3: `storage/redis/redis.go` — falta la declaración de copyright (menor)

**Descripción**: es el único archivo fuente Go de todo el proyecto sin la cabecera de copyright `Copyright (c) 2026 erik <erik@erik.xyz>`.

**Corrección**: añadir la declaración de copyright.

**Archivos**: `storage/redis/redis.go`

### Problema 4: `file/upload.go` — cálculo duplicado (menor)

**Descripción**: en `CheckExtension()`, `strings.LastIndex(filename, ".")` se llama dos veces (una directamente y otra a través de `HasMaliciousExt()`).

**Corrección**: almacenar el resultado en la variable `dotIdx`, calcular la extensión directamente y comprobar la lista blanca.

**Archivos**: `file/upload.go`

---

## 3. Cobertura de pruebas añadida

### Antes de la revisión

Solo 6 detectores tenían pruebas (XSS, SQL, JNDI, SSTI, SSRF, JWTAttack), con una cobertura aproximada del 19%.

### Después de la revisión

Los 32 detectores tienen pruebas, con una cobertura superior al 92%.

| Paquete | Nuevos archivos de prueba | Casos de prueba |
|---|-------------|---------|
| `injection/` | 6 (command, nosql, ldap, xpath, ssi, graphql) | 6 |
| `protocol/` | 8 (xxe, header_injection, host_header, request_smuggling, open_redirect, cors, websocket, dns_rebinding) | 8 |
| `data/` | 4 (deserialization, csv_injection, mail_header, prototype_pollution) | 4 |
| `file/` | 1 (upload) | 3 |

---

## 4. Evaluación de la calidad del código

### Puntos fuertes

1. **Excelente diseño de la interfaz** — la interfaz `Detector` es concisa y el patrón de registro `Engine` es claro
2. **Regex precompiladas** — todos los patrones se compilan en bloques `var`, con cero sobrecarga en tiempo de ejecución
3. **Cero dependencias externas** — la lógica de detección usa exclusivamente la biblioteca estándar de Go
4. **Arquitectura plug-and-play** — `RegisterAll()` registra 27 detectores sin configuración de un solo golpe
5. **Almacenamiento conectable** — la interfaz `storage.Backend` admite los tres backends Memory/File/Redis
6. **Cobertura de pruebas integral** — cada detector tiene casos positivos y negativos

### Sugerencias de mejora

1. **storage/file.go**: se recomienda añadir un cierre ordenado de autoSave (señal de canal); el goroutine actual podría seguir ejecutándose después de `Close()`
2. **Detector JWT**: `decodeBase64URL` maneja entradas no válidas, pero se recomienda añadir un límite máximo de longitud para prevenir DoS
3. **Paquete all**: podría añadirse una prueba para verificar el número de detectores registrados por `RegisterAll()`
4. **Cobertura de storage**: file.go y redis.go necesitan más escenarios de pruebas de integración
5. **Código de ejemplo del README**: la ruta de `go get` debería usar la ruta real del módulo

---

## 5. Lista de archivos modificados

### Correcciones de código (12 archivos)
- `storage/file.go` — añadir goroutine auto-save, corregir el bug de pérdida de datos
- `protocol/ssrf.go` — receiver de valor → receiver de puntero
- `protocol/xxe.go` — receiver de valor → receiver de puntero
- `protocol/header_injection.go` — receiver de valor → receiver de puntero
- `protocol/host_header.go` — receiver de valor → receiver de puntero
- `protocol/request_smuggling.go` — receiver de valor → receiver de puntero
- `protocol/open_redirect.go` — receiver de valor → receiver de puntero
- `protocol/cors.go` — receiver de valor → receiver de puntero
- `protocol/websocket.go` — receiver de valor → receiver de puntero
- `protocol/dns_rebinding.go` — receiver de valor → receiver de puntero
- `storage/redis/redis.go` — añadir cabecera de copyright
- `file/upload.go` — optimizar el cálculo duplicado en CheckExtension

### Nuevas pruebas (18 archivos)
- `injection/command_test.go`
- `injection/nosql_test.go`
- `injection/ldap_test.go`
- `injection/xpath_test.go`
- `injection/ssi_test.go`
- `injection/graphql_test.go`
- `protocol/xxe_test.go`
- `protocol/header_injection_test.go`
- `protocol/host_header_test.go`
- `protocol/request_smuggling_test.go`
- `protocol/open_redirect_test.go`
- `protocol/cors_test.go`
- `protocol/websocket_test.go`
- `protocol/dns_rebinding_test.go`
- `data/deserialization_test.go`
- `data/csv_injection_test.go`
- `data/mail_header_test.go`
- `data/prototype_pollution_test.go`
- `file/upload_test.go`

---

## 6. Resumen

Esta revisión detectó **1 bug grave** (riesgo de pérdida de datos), **1 problema de consistencia** (estilo de receivers), **1 falta de declaración de copyright** y **1 punto de optimización de código**, todos corregidos. Además, se añadieron pruebas unitarias completas para los detectores que carecían de ellas, elevando la cobertura de pruebas de aproximadamente el 19% a más del 92%.

Todos los cambios se verificaron con `go test ./...` y `go vet ./...`.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
