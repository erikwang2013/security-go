# Security Go — библиотека обнаружения атак

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Документация API](api.md)

Пакет обнаружения атак на Go, охватывающий **36 детектора**, **6 основных категорий атак**, **3 подключаемых бэкенда хранилища**. Единый интерфейс + паттерн реестра, чистая библиотека обнаружения, подходит для любого Go HTTP-фреймворка.

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>Талисман проекта Sentinel Gopher(哨兵鼠) — гофер Go, стоящий на страже со щитом. Число 36 на щите — это количество детекторов, а лупа — это сканирование каждого запроса.</sub>
</p>

[Архитектура](#архитектура) · [Реализованные функции](#реализованные-функции) · [Жизненный цикл](#жизненный-цикл) · [Структура проекта](#структура-проекта) · [Талисман](#талисман)

## Идея дизайна

### Основные принципы

- **Обнаружение без зависимостей** — все детекторы используют только стандартную библиотеку Go `regexp`, без внешних зависимостей
- **Единый интерфейс** — каждый детектор реализует интерфейс `Detector` (`Name()` + `Detect()`), управляемый через реестр `Engine`
- **Предкомпилированные регулярные выражения** — все шаблоны компилируются при инициализации `var`, нулевые накладные расходы во время выполнения
- **Конфигурация по требованию** — детекторы инъекций/протоколов/данных/файлов работают по принципу «подключи и работай»; HTTP-валидаторы и безопасность сессий требуют собственной конфигурации приложения

### Архитектура

![Архитектура](../../../docs/images/architecture.svg)

> Пакет `session` не регистрируется в `Engine`: для проверки сессии нужно прочитать полный `*http.Request` (token, IP-адрес клиента, User-Agent),
> и приложение должно предоставить хранилище и ключ, поэтому он вызывается напрямую как мидлвар — см. ниже «Конфигурация безопасности сессий».

### Жизненный цикл

Полный цикл запроса — от входа через обнаружение до градуированной обработки (включая цикл блокировки IP и повторное сканирование после URL-декодирования), а также путь сессии от привязки до отзыва:

![Жизненный цикл](../../../docs/images/lifecycle.svg)

### Уровни серьёзности

| Уровень | Описание | Типичные сценарии |
|------|------|---------|
| `SeverityLow` | Низкий риск | Неразрешённый HTTP-метод, несоответствие Content-Type |
| `SeverityMedium` | Средний риск | Слабые сигналы: ошибки конфигурации CORS, открытое перенаправление, интроспекция GraphQL, а также бесконтекстные шаблоны, которые каждый детектор намеренно выносит отдельно (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, обратные кавычки, `{#…#}`, `__proto__:`, имена магических методов PHP) — они часты в учебниках и обычном контенте |
| `SeverityHigh` | Высокий риск | Сильные сигналы: XSS, SQL-инъекция, SSRF, обход пути, аномалии сессии |
| `SeverityCritical` | Критический | Сильные сигналы: инъекция команд, JNDI, SSTI, XXE, утечка данных, десериализация (сериализованные объекты PHP / pickle / Java / .NET) |

## Реализованные функции

### Обзор возможностей

![Дизайн функций](../../../docs/images/features.svg)

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
| **DNS-ребиндинг** | внутренние IP в заголовке Host, localhost, короткие имена хостов без TLD |

### Валидация на уровне HTTP-протокола (7)
| **Глубина вложенности JSON** | Потоковый разбор через `json.Decoder`: помечает JSON-бомбу при превышении глубины вложенности или числа элементов (глубина по умолчанию 32). Некорректный или обрезанный JSON не срабатывает никогда |
| **Атрибуты Set-Cookie** | Отслеживает `Set-Cookie` без `Secure`/`HttpOnly`/`SameSite`, со слишком длинным или пустым значением; отсутствующие атрибуты собираются в один результат |

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
| **Десериализация** | сериализованные объекты `O:число:` / `C:число:`, `unserialize()`, магические методы (`__wakeup`/`__destruct`); покрывает полезные нагрузки PHP / pickle / Java / .NET |
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

### Безопасность сессий (2)

| Детектор | Обнаруживаемые шаблоны |
|--------|---------|
| **Защита сессии** (`session_guard`) | привязка token к клиенту, установленная при создании сессии, сравнение при каждом запросе: изменение User-Agent или отпечатка устройства определяется как **перехват клиента** (Critical); попадание IP-адреса клиента в другую подсеть или страну определяется как **удалённый вход** (High/Critical); `Observe()` при входе сравнивает исторические подсети и предупреждает при появлении новой. Сессия продлевается скользящим образом, `Revoke()` аннулирует её немедленно; `RecordFailure()` считает неудачные попытки и блокирует токен при достижении порога внутри окна, `Check()` сообщает `token_locked`, а `ClearFailures()` сбрасывает счётчик после успешного входа; `CheckLogin()` дополнительно ловит credential stuffing (один клиент, проваливающийся против слишком многих разных идентификаторов, даёт `credential_stuffing`), а блокировка удваивается с каждым повтором, до 24 ч |
| **Подмена данных** (`data_tamper`) | HMAC-SHA256-подпись параметров запроса (`timestamp.nonce.signature`), распознаёт изменение параметров, несовместимость ключа, выход временной метки за допуск, повтор подписи (счётчик nonce) |

### Бэкенды хранилища (3)

| Бэкенд | Описание |
|------|------|
| **Memory** | `sync.Mutex` + map, автоматическая очистка устаревших записей каждые 30 с |
| **File** | JSON-персистентность на диск, flush при Close |
| **Redis** | отдельный подмодуль, Pipeline Incr + TTL, требуется `go-redis/v9` |

## Структура проекта

```
security-go/
├── security.go            # Ядро: Result / Severity / интерфейс Detector / реестр Engine
├── injection/             # Детекторы инъекций (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # Детекторы протоколов и запросов (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # Детекторы данных и сериализации (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # Детекторы файлов и чувствительных данных (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # Валидаторы HTTP-протокола (7), каждому нужны настройки от приложения
├── session/               # Безопасность сессий (2): session_guard, data_tamper
│                          #   Обходит Engine и используется напрямую как мидлвар
├── storage/               # Бэкенды хранилища
│   ├── storage.go         #   Интерфейс Backend: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map, фоновая очистка каждые 30 с
│   ├── file.go            #   File: JSON-персистентность, flush при Close
│   └── redis/             #   Redis: отдельный подмодуль со своим go.mod
├── all/                   # Регистрация 27 детекторов без конфигурации одним вызовом
├── pet/                   # Талисман проекта: встроенный SVG + стартовый баннер
├── docs/
│   ├── api.md             # Справочник по API
│   ├── images/            # SVG архитектуры / функций / жизненного цикла
│   ├── i18n/              # Переведённая документация (12 языков)
│   └── superpowers/       # Спецификация дизайна, план реализации, отчёты о ревью кода
└── tests/                 # Отчёты о покрытии
```

Каждый пакет детектора составляет пару `xxx.go` и `xxx_test.go`; пакет `all` дополнительно несёт регрессионные тесты.

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
    all.RegisterAll(e) // регистрирует все 27 детекторов без конфигурации

    // Одиночное обнаружение
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("Обнаружено: %v, серьёзность: %d\n", r.Detected, r.Severity)

    // Полное обнаружение
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
            log.Printf("Обнаружена атака: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### Конфигурация HTTP-валидаторов

```go
// Проверка метода
e.Register(&httpval.Method{})

// Ограничение размера тела запроса
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Белый список Content-Type
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Проверка CSRF Origin
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP-чёрный список (автоблокировка: 5 атак/60 с → блокировка на 15 минут)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// Запись при атаке
blocked, _ := bl.RecordAttack(clientIP)
```

### Конфигурация безопасности сессий

Пакет `session` используется напрямую как мидлвар, минуя `Engine`. Хранилище должно быть предоставлено приложением (по умолчанию доступна реализация в памяти, которую можно заменить, например, на Redis):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // Опционально: подключите GeoIP для выявления входов из других стран

// Привязка сессии после успешного входа (token создаёт ваш сценарий входа)
// Обнаружение удалённого входа: сравнение с историческими подсетями пользователя, предупреждение при появлении новой
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // привязка token → подсеть IP / UA / отпечаток устройства
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// Защищённый маршрут: при перехвате или удалённом входе сразу возвращается 401
mux.Handle("/api/", tr.Guard(apiHandler))

// Или только обнаружение с самостоятельным решением
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// Выход из системы
tr.Revoke(token)
```

Обнаружение подмены данных: клиент и сервер совместно используют ключ, клиент подписывает параметры, сервер пересчитывает подпись и проверяет её:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // второй аргумент блокирует повтор подписи, может быть nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // клиент: отправляется вместе с параметрами

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` по умолчанию отключён: `X-Forwarded-For` / `X-Real-IP` контролируются клиентом, включайте только за собственным обратным прокси.
> `FailClosed` по умолчанию отключён (при сбое хранилища запрос пропускается, как и в `IPBlacklist`); для чувствительных к сессиям сервисов рекомендуется включить.

### Собственный детектор

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "обнаружено вредоносное содержимое",
    }
}

e.Register(&MyDetector{})
```

### Талисман

Пакет `pet` встраивает Sentinel Gopher как SVG на этапе компиляции через `go:embed` — без зависимости от файлов во время выполнения и без добавления сторонних зависимостей:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // стартовый баннер: простой текст, удобный для терминала
http.Handle("/pet.svg", pet.Handler()) // отладочный маршрут: отдаётся как image/svg+xml, кэш на сутки
svg := pet.SVG()                       // или возьмите сырые байты SVG
```

### Связанные документы

- [Документация API](api.md) — основные типы, интерфейсы Detector/Engine, интерфейс бэкенда хранилища, HTTP-валидаторы
- [Спецификация дизайна](specs/2026-07-29-attack-detection-design.md) — структура пакетов, каталог детекторов
- [План реализации](plans/2026-07-29-attack-detection-plan.md) — пошаговый план задач и сопоставление отклонений реализации
- [Отчёт о ревью кода](reports/2026-07-29-code-review-report.md) — исправления багов, покрытие тестами, оценка архитектуры
- [Отчёт о ревью кода v2](reports/2026-07-29-code-review-report-v2.md) — Второй проход: исправлено 4 проблемы, добавлено 18 тестовых файлов

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
