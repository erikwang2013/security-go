# Security Go — библиотека обнаружения атак

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Документация API](api.md)

Пакет обнаружения атак на Go, охватывающий **32 детектора**, **5 основных категорий атак**, **3 подключаемых бэкенда хранилища**. Единый интерфейс + паттерн реестра, чистая библиотека обнаружения, подходит для любого Go HTTP-фреймворка.

## Идея дизайна

### Основные принципы

- **Обнаружение без зависимостей** — все детекторы используют только стандартную библиотеку Go `regexp`, без внешних зависимостей
- **Единый интерфейс** — каждый детектор реализует интерфейс `Detector` (`Name()` + `Detect()`), управляемый через реестр `Engine`
- **Предкомпилированные регулярные выражения** — все шаблоны компилируются при инициализации `var`, нулевые накладные расходы во время выполнения
- **Конфигурация по требованию** — детекторы инъекций/протоколов/данных/файлов работают по принципу «подключи и работай»; HTTP-валидаторы требуют собственной конфигурации

### Архитектура

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

### Поток данных

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

### Уровни серьёзности

| Уровень | Описание | Типичные сценарии |
|------|------|---------|
| `SeverityLow` | Низкий риск | Неразрешённый HTTP-метод, несоответствие Content-Type |
| `SeverityMedium` | Средний риск | Проблемы конфигурации CORS, открытое перенаправление, интроспекция GraphQL |
| `SeverityHigh` | Высокий риск | XSS, SQL-инъекция, SSRF, обход пути |
| `SeverityCritical` | Критический | Инъекция команд, JNDI, SSTI, XXE, утечка данных |

## Реализованные функции

### Атаки типа «инъекция» (10)

| Детектор | Обнаруживаемые шаблоны |
|--------|---------|
| **XSS** | `<script>`, обработчики событий `on[a-z]+=`, псевдопротокол `javascript:`, SVG/CSS-инъекция, `eval()`, `document.cookie` |
| **SQL-инъекция** | `UNION SELECT` (в т.ч. обход через `/**/`), `sleep/benchmark/pg_sleep`, логическая слепая инъекция, перечисление `information_schema`, `xp_cmdshell` |
| **Инъекция команд** | обратные кавычки, `$()`, конвейер `\|`, `/dev/tcp`, PHP-функции `system/exec/shell_exec`, цепочки команд `&&` `;` `\|\|` |
| **NoSQL-инъекция** | операторы MongoDB `$ne` `$gt` `$regex` `$where`, `$func`, инъекция JSON-ключей |
| **LDAP-инъекция** | операторы фильтров `(\|(&(!`, `objectClass=*`, обход через URL-кодирование |
| **XPATH-инъекция** | логический обход `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, обфускация `${lower:j}`, переменные окружения `${env:}`, протоколы `ldap/rmi/dns` |
| **SSI-инъекция** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL-инъекция** | интроспекция `__schema`/`__type`, глубоко вложенный DoS (5+ уровней), обнаружение `mutation` |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, обход MRO в Python, доступ к `config/self` |

### Протокольные и запросные атаки (9)

| Детектор | Обнаруживаемые шаблоны |
|--------|---------|
| **SSRF** | внутренние IP-адреса (127/10/172.16/192.168), `169.254.169.254`, IPv6 loopback, протоколы `gopher/dict/file/ftp` |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, параметрические сущности `%entity;`, объявление DOCTYPE |
| **Инъекция HTTP-заголовков** | CRLF `%0d%0a` / `\r\n`, инъекция Set-Cookie/Location/Content-Length |
| **Атака на заголовок Host** | инъекция CRLF в Host, отравление `X-Forwarded-Host`, `X-Original-URL` |
| **Контрабанда запросов** | несоответствие Transfer-Encoding/Content-Length, двойной заголовок TE, обфускация сложенного заголовка `\x0b` |
| **Открытое перенаправление** | протокол-относительные URL `//evil.com`, псевдопротоколы `javascript:/data:` |
| **Обход CORS** | `Origin: null`, инъекция заголовков `Access-Control-Allow-*` |
| **Перехват WebSocket** | инъекция заголовка Upgrade, обход через null Origin, URL `ws://` |
| **DNS-ребinding** | внутренние IP в заголовке Host, localhost, короткие имена хостов без TLD |

### Валидация на уровне HTTP-протокола (5)

| Детектор | Описание |
|--------|------|
| **HTTP-метод** | разрешены только GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH, остальные вызывают предупреждение |
| **Размер тела запроса** | предупреждение при превышении лимита (по умолчанию 10 МБ) |
| **Content-Type** | разрешён только сконфигурированный белый список MIME-типов |
| **CSRF Origin** | проверка соответствия Origin и Host для кросс-доменных запросов, поддержка дополнительного белого списка |
| **IP-чёрный список** | автоматическая блокировка после N атак за окно времени (по умолчанию 5 раз/60 с → блокировка на 15 минут), поддержка хранилищ File/Redis/Memory |

### Атаки на данные и сериализацию (5)

| Детектор | Обнаруживаемые шаблоны |
|--------|---------|
| **Десериализация PHP** | сериализованные объекты `O:число:` / `C:число:`, `unserialize()`, магические методы (`__wakeup`/`__destruct`) |
| **CSV-инъекция** | `=cmd\|`, `@SUM(`, префиксы формул `+`/`-`, `HYPERLINK`/`DDE` |
| **Инъекция в заголовки почты** | инъекция Bcc/Cc/From/To, MIME multipart, параметр boundary |
| **Атаки на JWT** | обход через `alg: none`, обход пути `kid`, обнаружение пустой подписи (анализ структурного декодирования) |
| **Загрязнение прототипа** | ключи `__proto__`/`constructor`, `__defineGetter__`/`__defineSetter__` |

### Файлы и чувствительные данные (3)

| Детектор | Обнаруживаемые шаблоны |
|--------|---------|
| **Обход пути** | `../`, `..\\`, `php://filter`/`php://input`, null-байт, обход через URL-кодирование, `/etc/passwd` |
| **Вредоносная загрузка** | белый список расширений (15) + сканирование содержимого на PHP-теги `<?php`/`<?=` |
| **Утечка данных** | номера кредитных карт, AWS Access Key, приватные ключи `-----BEGIN`, строки подключения к БД, API-токены, JWT Secret, GitHub PAT |

### Бэкенды хранилища (3)

| Бэкенд | Описание |
|------|------|
| **Memory** | `sync.Mutex` + map, автоматическая очистка устаревших записей каждые 30 с |
| **File** | JSON-персистентность на диск, flush при Close |
| **Redis** | отдельный подмодуль, Pipeline Incr + TTL, требуется `go-redis/v9` |

## Использование

### Установка

```bash
go get github.com/erikwang2013/security-go
```

### Быстрый старт

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

### Обнаружение в HTTP-запросах

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

### Конфигурация HTTP-валидаторов

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

### Собственный детектор

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

### Связанные документы

- [Документация API](api.md) — основные типы, интерфейсы Detector/Engine, интерфейс бэкенда хранилища, HTTP-валидаторы
- [Спецификация дизайна](specs/2026-07-29-attack-detection-design.md) — структура пакетов, каталог детекторов
- [План реализации](plans/2026-07-29-attack-detection-plan.md) — пошаговый план задач и сопоставление отклонений реализации
- [Отчёт о ревью кода](reports/2026-07-29-code-review-report.md) — исправления багов, покрытие тестами, оценка архитектуры

---

## Документация на разных языках

| Язык | Документ |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [README.md](README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

Полный индекс: [docs/i18n/README.md](../README.md)

---

## Поддержка (пожертвования)

Если этот проект оказался для вас полезным, вы можете поддержать автора:

| Способ | QR-код |
|------|--------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### Международные банковские переводы

**Информация о получателе**

- Имя получателя: WANG KEXUN
- Номер счёта получателя: 881015918251

**Банк получателя (ZA Bank)**

- SWIFT-код: `AABLHKHHXXX`
- Название банка: ZA Bank Limited
- Банковский код: 387
- Адрес банка: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Банк-посредник для международных переводов (при необходимости)**

> Обратите внимание: это информация о банке-посреднике для международных переводов, а не о банке получателя. Уточните в своём банке, требуется ли указывать банк-посредник.

- Для переводов в гонконгских долларах (HKD), китайских юанях (CNY) и долларах США (USD) банком-посредником является Citibank:
  - Название банка: Citibank N.A. Hong Kong
  - SWIFT-код: `CITIHKHXXXX`
  - Банковский код: 006
  - Название отделения: Hong Kong Branch
  - Код отделения: 391
  - Адрес банка: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- Для переводов в других валютах банком-посредником является BNY Mellon:
  - Название банка: THE BANK OF NEW YORK MELLON
  - SWIFT-код: `IRVTUS3NXXX`
  - Адрес банка: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

Полная документация на английском языке: [README-EN.md](../../../README-EN.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
