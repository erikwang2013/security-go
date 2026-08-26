# Informe de revisión de código de Security-Go

**Fecha**: 2026-07-29  
**Proyecto**: github.com/erikwang2013/security-go  
**Alcance de la revisión**: 42 archivos fuente Go, 8 paquetes (security, all, data, file, httpval, injection, protocol, storage)

---

## 1. Resultados de las pruebas

```
ok      github.com/erikwang2013/security-go       0.004s
?       github.com/erikwang2013/security-go/all   [no test files]
ok      github.com/erikwang2013/security-go/data  0.005s
ok      github.com/erikwang2013/security-go/file  0.006s
ok      github.com/erikwang2013/security-go/httpval 0.004s  (已补写 32 个测试)
ok      github.com/erikwang2013/security-go/injection 0.005s
ok      github.com/erikwang2013/security-go/protocol  0.005s
ok      github.com/erikwang2013/security-go/storage   0.159s
```

- `go vet ./...` aprobado, sin advertencias
- Todas las pruebas pasan
- **Paquete sin pruebas**: `all` (el único restante)

---

## 2. Bugs corregidos

### Bug #1 [Crítico] `storage/file.go:101` — el error de serialización JSON se ignoraba silenciosamente

**Problema**: en el método `Close()`, `data, _ := json.Marshal(out)` ignoraba el error de serialización. Si la serialización JSON fallaba, `data` era nil y `os.WriteFile` escribía datos vacíos, **lo que provocaba la pérdida total de los datos persistidos**.

**Corrección**: comprobar el valor de retorno de error de `json.Marshal` y devolver el error de inmediato si falla.

```go
// 修复前
data, _ := json.Marshal(out)
return os.WriteFile(f.path, data, 0644)

// 修复后
data, err := json.Marshal(out)
if err != nil {
    return err
}
return os.WriteFile(f.path, data, 0644)
```

### Bug #2 [Crítico] `httpval/content_type.go:34` — AllowList vacío permitía todos los Content-Type

**Problema**: la condición `if len(c.Allowed) == 0 || c.Allowed[mt]` implicaba que, cuando AllowList estaba vacío, **se permitían todos los Content-Type**. El valor por defecto seguro debería ser deny-all.

**Corrección**: eliminar la condición `len(c.Allowed) == 0`; con AllowList vacío se entra en la rama de rechazo.

```go
// 修复前
if len(c.Allowed) == 0 || c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}

// 修复后
if c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}
```

### Bug #3 [Medio] `protocol/xxe.go:15` — `&[a-z]+;` coincidía erróneamente con todas las entidades HTML/XML válidas

**Problema**: la regex `(?i)&[a-z]+;` coincidía con todas las referencias de entidades estándar (`&amp;`, `&lt;`, `&gt;`, etc.), por lo que cualquier petición con HTML/XML válido se marcaba erróneamente como ataque XXE.

**Corrección**: reducir el rango de coincidencia a prefijos de protocolos maliciosos conocidos.

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. Problemas menores detectados (sin corregir, pendientes de evaluación)

### Problema #1: el paquete `all` no tiene cobertura de pruebas

La función `RegisterAll()` de `all/all.go` no tiene ninguna prueba. Debería añadirse una prueba que verifique que todos los detectores registrados pueden invocarse correctamente.

### Problema #2: pruebas del paquete `httpval` añadidas ✅ (resuelto)

Se ha añadido `httpval/httpval_test.go` (32 casos de prueba) que cubren `BodySize` (7 pruebas), `ContentType` (7 pruebas), `CSRFOrigin` (8 pruebas), `IPBlacklist` (6 pruebas) y `Method` (3 pruebas). Incluye valores límite, entradas erróneas y verificación deny-all con AllowList vacío.

### Problema #3: la regex de números de tarjeta de crédito en `data/data_leak.go` es demasiado amplia

`\b(?:\d[ -]*?){13,16}\b` coincide con cualquier secuencia de 13-16 dígitos.

### Problema #4: el submódulo `storage/redis/` está incompleto

- El `go.mod` carece de la declaración de dependencia del módulo padre
- Falta el archivo `go.sum`

### Problema #5: el estilo de receivers del paquete protocol difiere del paquete injection

- El paquete `injection` usa receivers de puntero: `func (d *XSS) Name() string`
- El paquete `protocol` usa receivers de valor: `func (d CORS) Name() string`

### Problema #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` coincide con referencias numéricas de caracteres HTML válidas

---

## 4. Evaluación general de la arquitectura

| Dimensión | Puntuación | Observaciones |
|------|------|------|
| Diseño de la interfaz | ★★★★☆ | La interfaz `Detector` + el patrón de orquestación `Engine` son claros |
| Consistencia del código | ★★★☆☆ | Estilo de receivers no uniforme |
| Manejo de errores | ★★★☆☆ | Antes de la corrección los errores se tragaban silenciosamente; después ha mejorado |
| Cobertura de pruebas | ★★★★☆ | Se han añadido pruebas para `httpval`; aún faltan para `all` |
| Valores por defecto seguros | ★★★☆☆ | El problema del AllowList vacío en ContentType ya está corregido |
| Precisión de detección | ★★★☆☆ | Algunas regex tienen riesgo de falsos positivos (xxe parcialmente corregido) |

---

## 5. Prioridades recomendadas

| Prioridad | Asunto |
|--------|------|
| ~~P0~~ | ~~Añadir pruebas del paquete `httpval`~~ ✅ completado (32 pruebas, 5 detectores) |
| P1 | Añadir pruebas del paquete `all` |
| P1 | Corregir el go.mod del submódulo `storage/redis/` |
| P2 | Unificar el estilo de receivers a receivers de puntero |
| P2 | Evaluar la tasa de falsos positivos de las regex de tarjetas de crédito/XSS |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
