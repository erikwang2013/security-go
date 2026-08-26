# Security Go — हमले का पता लगाने वाली लाइब्रेरी

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API दस्तावेज़](api.md)

Go भाषा में लिखा गया आक्रमण-पता लगाने वाला (attack detection) पैकेज, जिसमें **32 डिटेक्टर**, **5 प्रमुख आक्रमण श्रेणियाँ** और **3 प्लगेबल स्टोरेज बैकएंड** शामिल हैं। एकीकृत इंटरफ़ेस + रजिस्ट्री पैटर्न, शुद्ध डिटेक्शन लाइब्रेरी — किसी भी Go HTTP फ्रेमवर्क के अनुकूल।

## डिज़ाइन विचार

### मुख्य सिद्धांत

- **शून्य-निर्भरता डिटेक्शन** — सभी डिटेक्टर केवल Go मानक लाइब्रेरी `regexp` का उपयोग करते हैं, कोई बाहरी निर्भरता नहीं
- **एकीकृत इंटरफ़ेस** — प्रत्येक डिटेक्टर `Detector` इंटरफ़ेस लागू करता है (`Name()` + `Detect()`), जिसे `Engine` रजिस्ट्री के माध्यम से केंद्रीय रूप से प्रबंधित किया जाता है
- **प्री-कंपाइल्ड regex** — सभी पैटर्न `var` इनिशियलाइज़ेशन के समय कंपाइल हो जाते हैं, रनटाइम पर शून्य ओवरहेड
- **आवश्यकता अनुसार कॉन्फ़िगरेशन** — इंजेक्शन/प्रोटोकॉल/डेटा/फ़ाइल डिटेक्टर प्लग-एंड-प्ले हैं; HTTP वैलिडेटर के लिए एप्लिकेशन-विशिष्ट कॉन्फ़िगरेशन आवश्यक है

### डिज़ाइन आर्किटेक्चर

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

### डेटा फ़्लो

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

### गंभीरता स्तर

| स्तर | विवरण | विशिष्ट परिदृश्य |
|------|--------|-----------------|
| `SeverityLow` | कम जोखिम | अमान्य HTTP विधि, Content-Type बेमेल |
| `SeverityMedium` | मध्यम जोखिम | CORS कॉन्फ़िगरेशन समस्या, ओपन रीडायरेक्ट, GraphQL इंट्रोस्पेक्शन |
| `SeverityHigh` | उच्च जोखिम | XSS, SQL इंजेक्शन, SSRF, पाथ ट्रैवर्सल |
| `SeverityCritical` | गंभीर | कमांड इंजेक्शन, JNDI, SSTI, XXE, डेटा लीक |

## कार्यान्वित सुविधाएँ

### इंजेक्शन-प्रकार के आक्रमण (10)

| डिटेक्टर | डिटेक्शन पैटर्न |
|----------|------------------|
| **XSS** | `<script>`, `on[a-z]+=` इवेंट हैंडलर, `javascript:` स्यूडो-प्रोटोकॉल, SVG/CSS इंजेक्शन, `eval()`, `document.cookie` |
| **SQL इंजेक्शन** | `UNION SELECT` (`/**/` बायपास सहित), `sleep/benchmark/pg_sleep`, बूलियन ब्लाइंड, `information_schema` एन्यूमरेशन, `xp_cmdshell` |
| **कमांड इंजेक्शन** | बैकटिक, `$()`, पाइप, `/dev/tcp`, PHP `system/exec/shell_exec`, चेन एक्ज़ीक्यूशन `&&` `;` `\|\|` |
| **NoSQL इंजेक्शन** | MongoDB `$ne` `$gt` `$regex` `$where` ऑपरेटर, `$func`, JSON कुंजी इंजेक्शन |
| **LDAP इंजेक्शन** | फ़िल्टर ऑपरेटर `(\|(&(!`, `objectClass=*`, URL-एन्कोडिंग बायपास |
| **XPATH इंजेक्शन** | बूलियन बायपास `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, `${lower:j}` ऑबफ़स्केशन, `${env:}` एनवायरनमेंट वेरिएबल, `ldap/rmi/dns` प्रोटोकॉल |
| **SSI इंजेक्शन** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL इंजेक्शन** | `__schema`/`__type` इंट्रोस्पेक्शन, डीप-नेस्टेड DoS (5+ लेवल), `mutation` डिटेक्शन |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO ट्रैवर्सल, `config/self` एक्सेस |

### प्रोटोकॉल और अनुरोध आक्रमण (9)

| डिटेक्टर | डिटेक्शन पैटर्न |
|----------|------------------|
| **SSRF** | इंटरनल IP (127/10/172.16/192.168), `169.254.169.254`, IPv6 loopback, `gopher/dict/file/ftp` प्रोटोकॉल |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, पैरामीटर एंटिटी `%entity;`, DOCTYPE घोषणा |
| **HTTP हेडर इंजेक्शन** | CRLF `%0d%0a` / `\r\n`, Set-Cookie/Location/Content-Length इंजेक्शन |
| **Host हेडर आक्रमण** | CRLF Host इंजेक्शन, `X-Forwarded-Host`, `X-Original-URL` पॉइज़निंग |
| **रिक्वेस्ट स्मगलिंग** | Transfer-Encoding/Content-Length बेमेल, दोहरा TE हेडर, `\x0b` फोल्डेड हेडर ऑबफ़स्केशन |
| **ओपन रीडायरेक्ट** | `//evil.com` प्रोटोकॉल-रिलेटिव URL, `javascript:/data:` स्यूडो-प्रोटोकॉल |
| **CORS बायपास** | `Origin: null`, `Access-Control-Allow-*` हेडर इंजेक्शन |
| **WebSocket हाईजैकिंग** | Upgrade हेडर इंजेक्शन, null Origin बायपास, `ws://` URL |
| **DNS रीबाइंडिंग** | Host हेडर में इंटरनल IP, localhost, बिना TLD वाले छोटे होस्टनेम |

### HTTP प्रोटोकॉल लेयर वैलिडेशन (5)

| डिटेक्टर | विवरण |
|----------|--------|
| **HTTP विधि** | केवल GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH अनुमत, बाकी पर चेतावनी |
| **रिक्वेस्ट बॉडी साइज़** | सीमा (डिफ़ॉल्ट 10MB) से अधिक होने पर चेतावनी |
| **Content-Type** | केवल कॉन्फ़िगर किए गए MIME टाइप व्हाइटलिस्ट की अनुमति |
| **CSRF Origin** | क्रॉस-डोमेन अनुरोधों में Origin और Host मेल खाते हैं या नहीं, अतिरिक्त व्हाइटलिस्ट सपोर्ट |
| **IP ब्लैकलिस्ट** | विंडो समय में N आक्रमण के बाद स्वतः ब्लॉक (डिफ़ॉल्ट 5 बार/60s → 15 मिनट ब्लॉक), File/Redis/Memory स्टोरेज सपोर्ट |

### डेटा और सीरियलाइज़ेशन आक्रमण (5)

| डिटेक्टर | डिटेक्शन पैटर्न |
|----------|------------------|
| **PHP डिसीरियलाइज़ेशन** | `O:अंक:` / `C:अंक:` सीरियलाइज़्ड ऑब्जेक्ट, `unserialize()`, मैजिक मेथड (`__wakeup`/`__destruct`) |
| **CSV इंजेक्शन** | `=cmd\|`, `@SUM(`, `+`/`-` फॉर्मूला प्रीफ़िक्स, `HYPERLINK`/`DDE` |
| **मेल हेडर इंजेक्शन** | Bcc/Cc/From/To इंजेक्शन, MIME multipart, boundary पैरामीटर |
| **JWT आक्रमण** | `alg: none` बायपास, `kid` पाथ ट्रैवर्सल, खाली सिग्नेचर डिटेक्शन (संरचनात्मक डीकोड विश्लेषण) |
| **प्रोटोटाइप पोल्यूशन** | `__proto__`/`constructor` कुंजी, `__defineGetter__`/`__defineSetter__` |

### फ़ाइल और संवेदनशील डेटा (3)

| डिटेक्टर | डिटेक्शन पैटर्न |
|----------|------------------|
| **पाथ ट्रैवर्सल** | `../`, `..\\`, `php://filter`/`php://input`, null बाइट, URL-एन्कोडिंग बायपास, `/etc/passwd` |
| **दुर्भावनापूर्ण अपलोड** | एक्सटेंशन व्हाइटलिस्ट (15 प्रकार) + PHP टैग `<?php`/`<?=` कंटेंट स्कैन |
| **डेटा लीक** | क्रेडिट कार्ड नंबर, AWS Access Key, प्राइवेट की `-----BEGIN`, डेटाबेस कनेक्शन स्ट्रिंग, API टोकन, JWT Secret, GitHub PAT |

### स्टोरेज बैकएंड (3)

| बैकएंड | विवरण |
|---------|--------|
| **Memory** | `sync.Mutex` + map, 30s में एक्सपायर्ड एंट्रीज़ स्वतः साफ़ होती हैं |
| **File** | JSON फ़ाइल पर्सिस्टेंस, Close होने पर flush |
| **Redis** | स्वतंत्र सबमॉड्यूल, Pipeline Incr + TTL, `go-redis/v9` आवश्यक |

## उपयोग निर्देश

### इंस्टॉलेशन

```bash
go get github.com/erikwang2013/security-go
```

### त्वरित शुरुआत

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

### HTTP अनुरोध डिटेक्शन

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

### HTTP वैलिडेटर कॉन्फ़िगरेशन

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

### कस्टम डिटेक्टर

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

### संबंधित दस्तावेज़

- [API दस्तावेज़](api.md) — मुख्य प्रकार, Detector/Engine इंटरफ़ेस, स्टोरेज बैकएंड इंटरफ़ेस, HTTP वैलिडेटर
- [डिज़ाइन स्पेक](specs/2026-07-29-attack-detection-design.md) — पैकेज संरचना, डिटेक्टर सूची
- [कार्यान्वयन योजना](plans/2026-07-29-attack-detection-plan.md) — चरण-दर-चरण कार्य योजना और कार्यान्वयन विचलन
- [कोड समीक्षा रिपोर्ट](reports/2026-07-29-code-review-report.md) — Bug फिक्स, टेस्ट कवरेज, आर्किटेक्चर मूल्यांकन

---

## बहुभाषी दस्तावेज़

| भाषा | दस्तावेज़ |
|------|-----------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [README.md](README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

सभी भाषाओं की सूची: [docs/i18n/README.md](../README.md)

---

## दान समर्थन

यदि यह प्रोजेक्ट आपके लिए उपयोगी है, तो कृपया दान करके सहयोग करें:

| तरीका | QR कोड |
|-------|--------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### वैश्विक बैंक ट्रांसफ़र दान (वायर ट्रांसफ़र)

**प्राप्तकर्ता की जानकारी**

- प्राप्तकर्ता का नाम: WANG KEXUN
- खाता संख्या: 881015918251

**प्राप्ति बैंक (ZA Bank)**

- SWIFT Code: `AABLHKHHXXX`
- बैंक का नाम: ZA Bank Limited
- बैंक कोड: 387
- बैंक का पता: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**क्रॉस-बॉर्डर रेमिटेंस एजेंट बैंक (यदि आवश्यक हो)**

> कृपया ध्यान दें: यह क्रॉस-बॉर्डर रेमिटेंस एजेंट बैंक (मध्यस्थ बैंक) की जानकारी है, प्राप्ति बैंक की नहीं। कृपया अपने रेमिट करने वाले बैंक से पूछें कि क्या क्रॉस-बॉर्डर रेमिटेंस एजेंट बैंक की जानकारी देना आवश्यक है।

- हाँगकांग डॉलर, RMB और USD के लिए एजेंट बैंक Citibank है:
  - बैंक का नाम: Citibank N.A. Hong Kong
  - SWIFT Code: `CITIHKHXXXX`
  - बैंक कोड: 006
  - शाखा का नाम: Hong Kong Branch
  - शाखा कोड: 391
  - बैंक का पता: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- अन्य मुद्राओं के लिए एजेंट बैंक BNY Mellon है:
  - बैंक का नाम: THE BANK OF NEW YORK MELLON
  - SWIFT Code: `IRVTUS3NXXX`
  - बैंक का पता: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

पूर्ण अंग्रेज़ी दस्तावेज़ के लिए [README-EN.md](../../../README-EN.md) देखें।

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
