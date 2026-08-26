# Пакет обнаружения атак — план реализации

> **Для агентных исполнителей:** ОБЯЗАТЕЛЬНЫЙ ДОПОЛНИТЕЛЬНЫЙ НАВЫК: используйте superpowers:subagent-driven-development (рекомендуется) или superpowers:executing-plans для реализации этого плана по задачам.

**Цель:** создать чистую библиотеку обнаружения атак на Go с 32 детекторами в 5 категориях, 3 подключаемыми бэкендами хранилища и единым реестром Engine. **Статус: завершено (2026-07-29).**

**Архитектура:** плоский интерфейсный дизайн — каждый детектор реализует `Detector` (Name + Detect). Предкомпилированные регулярные выражения. Engine предоставляет реестр, поиск по имени и `DetectRequest` для сканирования полного HTTP-запроса. RegisterAll находится в `all/all.go` (отдельный пакет).

**Технологический стек:** Go 1.21+, стандартные `regexp` + `net/http`, `go-redis` для бэкенда Redis (опциональный подмодуль в `storage/redis/`).

---

### Задача 1: Инициализация Go-модуля и основных типов

**Файлы:**
- Создать: `go.mod`
- Создать: `security.go`

- [x] **Шаг 1: Инициализация Go-модуля**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **Шаг 2: Создание security.go — Result, Severity, интерфейс Detector, Engine**

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

- [x] **Шаг 3: Сборка** — `go build ./...`
- [x] **Шаг 4: Коммит** — `feat: initialize Go module with core types and Engine`

---

### Задача 2: Интерфейс бэкенда хранилища и Memory

**Файлы:**
- Создать: `storage/storage.go`
- Создать: `storage/memory.go`

- [x] **Шаг 1: storage/storage.go** — интерфейс Backend (Incr, Get, Block, IsBlocked, Close)
- [x] **Шаг 2: storage/memory.go** — реализация на основе sync.Map с goroutine очистки TTL
- [x] **Шаг 3: Сборка** — `go build ./storage/...`
- [x] **Шаг 4: Коммит** — `feat: add storage interface and memory backend`

---

### Задача 3: Файловое и Redis-хранилище

**Файлы:**
- Создать: `storage/file.go`
- Создать: `storage/redis.go`
- Изменить: `go.mod` (добавить зависимость go-redis)

- [x] **Шаг 1: storage/file.go** — JSON-персистентность на диск с отложенным flush
- [x] **Шаг 2: storage/redis.go** — бэкенд Redis на go-redis/v9
- [x] **Шаг 3: Сборка** — `go build ./storage/...`
- [x] **Шаг 4: Коммит** — `feat: add file and redis storage backends`

---

### Задача 4: Детекторы инъекций — XSS, SQL

**Файлы:**
- Создать: `injection/xss.go`
- Создать: `injection/sql.go`

- [x] **Шаг 1: injection/xss.go** — `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS-шаблоны
- [x] **Шаг 2: injection/sql.go** — UNION SELECT (с обходом через `/**/`), sleep/benchmark, логическая слепая инъекция, перечисление схемы, хранимые процедуры
- [x] **Шаг 3: Сборка** — `go build ./injection/...`
- [x] **Шаг 4: Коммит** — `feat: add XSS and SQL injection detectors`

---

### Задача 5: Детекторы инъекций — Command, NoSQL, LDAP, XPATH

**Файлы:**
- Создать: `injection/command.go`
- Создать: `injection/nosql.go`
- Создать: `injection/ldap.go`
- Создать: `injection/xpath.go`

- [x] **Шаг 1: injection/command.go** — обратные кавычки, `$()`, конвейер, `/dev/tcp`, PHP-функции exec
- [x] **Шаг 2: injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, обход аутентификации
- [x] **Шаг 3: injection/ldap.go** — операторы фильтров `(`, `)`, `&`, `|`, `*`
- [x] **Шаг 4: injection/xpath.go** — логический обход, string-length, count
- [x] **Шаг 5: Сборка и коммит**

---

### Задача 6: Детекторы инъекций — JNDI, SSI, GraphQL, SSTI

**Файлы:**
- Создать: `injection/jndi.go`
- Создать: `injection/ssi.go`
- Создать: `injection/graphql.go`
- Создать: `injection/ssti.go`

- [x] **Шаг 1: injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, протоколы rmi/dns
- [x] **Шаг 2: injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **Шаг 3: injection/graphql.go** — `__schema`, `__type`, глубоко вложенные запросы, mutation
- [x] **Шаг 4: injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, MRO в Python
- [x] **Шаг 5: Сборка и коммит**

---

### Задача 7: Протокольные детекторы — SSRF, XXE, Header Injection

**Файлы:**
- Создать: `protocol/ssrf.go`
- Создать: `protocol/xxe.go`
- Создать: `protocol/header_injection.go`

- [x] **Шаг 1: protocol/ssrf.go** — внутренние IP, 169.254.169.254, IPv6 loopback, gopher/dict
- [x] **Шаг 2: protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, параметрические сущности, DOCTYPE
- [x] **Шаг 3: protocol/header_injection.go** — CRLF, инъекция Set-Cookie/Location
- [x] **Шаг 4: Сборка и коммит**

---

### Задача 8: Протокольные детекторы — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**Файлы:**
- Создать: `protocol/host_header.go`
- Создать: `protocol/request_smuggling.go`
- Создать: `protocol/open_redirect.go`
- Создать: `protocol/cors.go`
- Создать: `protocol/websocket.go`
- Создать: `protocol/dns_rebinding.go`

- [x] **Шаг 1: Все 6 протокольных детекторов** — по одному файлу на каждый, предкомпилированные регулярные выражения
- [x] **Шаг 2: Сборка и коммит**

---

### Задача 9: HTTP-валидаторы

**Файлы:**
- Создать: `httpval/method.go`
- Создать: `httpval/body_size.go`
- Создать: `httpval/content_type.go`
- Создать: `httpval/csrf_origin.go`
- Создать: `httpval/ip_blacklist.go`

- [x] **Шаг 1: httpval/method.go** — белый список GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **Шаг 2: httpval/body_size.go** — проверка максимального размера, по умолчанию 10 МБ
- [x] **Шаг 3: httpval/content_type.go** — белый список MIME-типов
- [x] **Шаг 4: httpval/csrf_origin.go** — сопоставление кросс-доменных Origin и Host
- [x] **Шаг 5: httpval/ip_blacklist.go** — оконное ограничение частоты (5/60 с → блокировка на 15 минут), использует storage.Backend
- [x] **Шаг 6: Сборка и коммит**

---

### Задача 10: Детекторы данных и сериализации

**Файлы:**
- Создать: `data/deserialization.go`
- Создать: `data/csv_injection.go`
- Создать: `data/mail_header.go`
- Создать: `data/jwt_attack.go`
- Создать: `data/prototype_pollution.go`

- [x] **Шаг 1: data/deserialization.go** — PHP `O:число:`, `C:число:`, unserialize(), магические методы
- [x] **Шаг 2: data/csv_injection.go** — `=cmd|`, `@SUM(`, префиксы формул `+`, `-`
- [x] **Шаг 3: data/mail_header.go** — инъекция Bcc/Cc/From/To, MIME multipart
- [x] **Шаг 4: data/jwt_attack.go** — alg:none, обход пути kid, пустая подпись (структурное декодирование)
- [x] **Шаг 5: data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **Шаг 6: Сборка и коммит**

---

### Задача 11: Детекторы файлов и чувствительных данных

**Файлы:**
- Создать: `file/path_traversal.go`
- Создать: `file/upload.go`
- Создать: `file/data_leak.go`

- [x] **Шаг 1: file/path_traversal.go** — `../`, `..\\`, php://filter, null-байт, обход через URL-кодирование
- [x] **Шаг 2: file/upload.go** — белый список расширений + сканирование содержимого на PHP-теги
- [x] **Шаг 3: file/data_leak.go** — кредитные карты, AWS-ключи, приватные ключи, строки подключения к БД, API-токены, JWT-секреты
- [x] **Шаг 4: Сборка и коммит**

---

### Задача 12: Интеграция Engine — RegisterAll

**Файлы:**
- Изменить: `security.go`

- [x] **Шаг 1: Добавить RegisterAll()** — регистрирует все 32 встроенных детектора
- [x] **Шаг 2: Сборка** — `go build ./...`
- [x] **Шаг 3: Коммит** — `feat: add RegisterAll for built-in detectors`

---

### Задача 13: Тесты

**Файлы:**
- Создать: `security_test.go`
- Создать: `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Создать: `protocol/ssrf_test.go`
- Создать: `file/path_traversal_test.go`, `data_leak_test.go`
- Создать: `data/jwt_attack_test.go`
- Создать: `storage/memory_test.go`

- [x] **Шаг 1: Написать тесты** — с положительными и отрицательными тест-кейсами
- [x] **Шаг 2: Запуск** — `go test ./... -v`
- [x] **Шаг 3: Коммит** — `test: add core engine and detector tests`

---

### Задача 14: Пост-реализационное ревью кода и исправления (2026-07-29)

- [x] **Полное ревью кода** — 42 Go-исходных файла, 8 пакетов
- [x] **Исправление бага #1** — `storage/file.go`: ошибка JSON-сериализации молча игнорировалась → добавлена проверка ошибки с возвратом
- [x] **Исправление бага #2** — `httpval/content_type.go`: пустой AllowList пропускал все Content-Type → значение по умолчанию deny-all
- [x] **Исправление бага #3** — `protocol/xxe.go`: `&[a-z]+;` ложно сопоставлялся с легальными HTML-сущностями → сужено до списка известных вредоносных протоколов
- [x] **Дописаны тесты httpval** — 32 тест-кейса, покрывают 5 детекторов (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Полный прогон тестов** — `go test -count=1 ./...` 7/7 пакетов пройдено, `go vet` без предупреждений

---

## Отклонения: план против факта

| План | Факт | Причина |
|------|------|------|
| RegisterAll в `security.go` | отдельный пакет `all/all.go` | избежать циклических импортов: httpval зависит от storage, остальные детекторы — нет |
| Redis в корневом go.mod | подмодуль `storage/redis/` | изоляция опциональной зависимости |
| Единые указательные receiver | пакет protocol использовал value-ресиверы | ✅ в ревью v2 все заменены на указательные |
| Задачи 4-12: Build & Commit | без поэтапных коммитов | весь код реализован за один раз |

## Сводка по покрытию тестами

| Пакет | Тестовые файлы | Кол-во тестов |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (нет) | 0 |

> Полный отчёт см. в [отчёте о ревью v2](../reports/2026-07-29-code-review-report-v2.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
