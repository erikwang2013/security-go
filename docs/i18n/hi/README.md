# Security Go — हमले का पता लगाने वाली लाइब्रेरी

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API दस्तावेज़](api.md)

Go भाषा में लिखा गया आक्रमण-पता लगाने वाला (attack detection) पैकेज, जिसमें **36 डिटेक्टर**, **6 प्रमुख आक्रमण श्रेणियाँ** और **3 प्लगेबल स्टोरेज बैकएंड** शामिल हैं। एकीकृत इंटरफ़ेस + रजिस्ट्री पैटर्न, शुद्ध डिटेक्शन लाइब्रेरी — किसी भी Go HTTP फ्रेमवर्क के अनुकूल।

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>प्रोजेक्ट शुभंकर Sentinel Gopher (哨兵鼠) — ढाल के साथ पहरा देता एक Go गोफ़र। ढाल पर लिखा 36 डिटेक्टरों की संख्या है; आवर्धक लेंस प्रत्येक अनुरोध पर होने वाले स्कैन का प्रतीक है।</sub>
</p>

[आर्किटेक्चर](#डिज़ाइन-आर्किटेक्चर) · [सुविधाएँ](#कार्यान्वित-सुविधाएँ) · [जीवनचक्र](#जीवनचक्र) · [परियोजना संरचना](#परियोजना-संरचना) · [शुभंकर](#शुभंकर)

## डिज़ाइन विचार

### मुख्य सिद्धांत

- **शून्य-निर्भरता डिटेक्शन** — सभी डिटेक्टर केवल Go मानक लाइब्रेरी `regexp` का उपयोग करते हैं, कोई बाहरी निर्भरता नहीं
- **एकीकृत इंटरफ़ेस** — प्रत्येक डिटेक्टर `Detector` इंटरफ़ेस लागू करता है (`Name()` + `Detect()`), जिसे `Engine` रजिस्ट्री के माध्यम से केंद्रीय रूप से प्रबंधित किया जाता है
- **प्री-कंपाइल्ड regex** — सभी पैटर्न `var` इनिशियलाइज़ेशन के समय कंपाइल हो जाते हैं, रनटाइम पर शून्य ओवरहेड
- **आवश्यकता अनुसार कॉन्फ़िगरेशन** — इंजेक्शन/प्रोटोकॉल/डेटा/फ़ाइल डिटेक्टर प्लग-एंड-प्ले हैं; HTTP वैलिडेटर और सत्र सुरक्षा डिटेक्शन के लिए एप्लिकेशन-विशिष्ट कॉन्फ़िगरेशन आवश्यक है

### डिज़ाइन आर्किटेक्चर

![आर्किटेक्चर](../../../docs/images/architecture.svg)

> `session` पैकेज `Engine` रजिस्ट्री से नहीं गुज़रता: सत्र सत्यापन के लिए पूरा `*http.Request` (token, क्लाइंट IP, User-Agent) पढ़ना आवश्यक है,
> और एप्लिकेशन को स्टोरेज व कुंजी देनी होती है, इसलिए इसे सीधे मिडलवेयर के रूप में कॉल किया जाता है — नीचे "सत्र सुरक्षा कॉन्फ़िगरेशन" देखें।

### जीवनचक्र

अनुरोध का पूरा चक्र — प्रवेश से डिटेक्शन और फिर श्रेणीबद्ध हैंडलिंग तक (IP बैन चक्र और URL-डिकोड रीस्कैन सहित), तथा एक सत्र की बाइंडिंग से निरस्तीकरण तक की यात्रा:

![जीवनचक्र](../../../docs/images/lifecycle.svg)

### गंभीरता स्तर

| स्तर | विवरण | विशिष्ट परिदृश्य |
|------|--------|-----------------|
| `SeverityLow` | कम जोखिम | अमान्य HTTP विधि, Content-Type बेमेल |
| `SeverityMedium` | मध्यम जोखिम | कमज़ोर संकेत: CORS कॉन्फ़िगरेशन समस्या, ओपन रीडायरेक्ट, GraphQL इंट्रोस्पेक्शन, तथा वे संदर्भ-रहित पैटर्न जिन्हें हर डिटेक्टर जानबूझकर अलग रखता है (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, बैकटिक, `{#…#}`, `__proto__:`, PHP मैजिक मेथड नाम) — ट्यूटोरियल और सामान्य सामग्री में आम |
| `SeverityHigh` | उच्च जोखिम | मज़बूत संकेत: XSS, SQL इंजेक्शन, SSRF, पाथ ट्रैवर्सल, सत्र विसंगतियाँ |
| `SeverityCritical` | गंभीर | मज़बूत संकेत: कमांड इंजेक्शन, JNDI, SSTI, XXE, डेटा लीक, डीserialाइज़ेशन (PHP सीरियलाइज़्ड ऑब्जेक्ट / pickle / Java / .NET) |

## कार्यान्वित सुविधाएँ

### सुविधाओं का अवलोकन

![सुविधा डिज़ाइन](../../../docs/images/features.svg)

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

### HTTP प्रोटोकॉल लेयर वैलिडेशन (7)
| **JSON नेस्टिंग गहराई** | `json.Decoder` से स्ट्रीम स्कैन: नेस्टिंग गहराई या तत्व संख्या सीमा पार करने पर JSON बम पहचानता है (डिफ़ॉल्ट गहराई 32); अमान्य या कटा JSON कभी अलर्ट नहीं करता |
| **कुकी एट्रिब्यूट** | `Set-Cookie` में `Secure`/`HttpOnly`/`SameSite` अनुपस्थित, मान अत्यधिक लंबा या खाली होने पर पहचान; अनुपस्थित एट्रिब्यूट एक ही परिणाम में |

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
| **डिसीरियलाइज़ेशन** | `O:अंक:` / `C:अंक:` सीरियलाइज़्ड ऑब्जेक्ट, `unserialize()`, मैजिक मेथड (`__wakeup`/`__destruct`); PHP / pickle / Java / .NET पेलोड कवर करता है |
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

### सत्र सुरक्षा (2)

| डिटेक्टर | डिटेक्शन पैटर्न |
|----------|------------------|
| **सत्र गार्ड** (`session_guard`) | सत्र स्थापित होने के समय token की क्लाइंट से बाइंडिंग, प्रत्येक अनुरोध पर तुलना: User-Agent या डिवाइस फ़िंगरप्रिंट बदलने पर **क्लाइंट हाईजैक** (Critical) माना जाता है; क्लाइंट IP किसी अन्य सबनेट या देश में पहुँचने पर **रिमोट लॉगिन** (High/Critical) माना जाता है; `Observe()` लॉगिन के समय ऐतिहासिक सबनेट की तुलना करता है और नया सबनेट दिखते ही चेतावनी देता है। सत्र स्लाइडिंग नवीनीकरण करता है, `Revoke()` से तुरंत अमान्य किया जा सकता है; `RecordFailure()` विफल प्रयास गिनता है और विंडो में सीमा पार होते ही टोकन लॉक कर देता है, `Check()` तब `token_locked` रिपोर्ट करता है, और सफल लॉगिन पर `ClearFailures()` गिनती शून्य कर देता है; `CheckLogin()` इसके अतिरिक्त क्रेडेंशियल स्टफिंग पकड़ता है (एक क्लाइंट बहुत सी भिन्न पहचानों पर विफल हो तो `credential_stuffing`), और हर दोहराव पर लॉक दोगुना होता है, अधिकतम 24 घंटे |
| **डेटा टैंपरिंग** (`data_tamper`) | अनुरोध पैरामीटर पर HMAC-SHA256 सिग्नेचर (`टाइमस्टैम्प.nonce.सिग्नेचर`), पैरामीटर बदलाव, कुंजी बेमेल, टाइमस्टैम्प अंतराल से बाहर, और सिग्नेचर रीप्ले (nonce काउंटर) की पहचान |

### स्टोरेज बैकएंड (3)

| बैकएंड | विवरण |
|---------|--------|
| **Memory** | `sync.Mutex` + map, 30s में एक्सपायर्ड एंट्रीज़ स्वतः साफ़ होती हैं |
| **File** | JSON फ़ाइल पर्सिस्टेंस, Close होने पर flush |
| **Redis** | स्वतंत्र सबमॉड्यूल, Pipeline Incr + TTL, `go-redis/v9` आवश्यक |

## परियोजना संरचना

```
security-go/
├── security.go            # मुख्य: Result / Severity / Detector इंटरफ़ेस / Engine रजिस्ट्री
├── injection/             # इंजेक्शन डिटेक्टर (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # प्रोटोकॉल व अनुरोध डिटेक्टर (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # डेटा व सीरियलाइज़ेशन डिटेक्टर (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # फ़ाइल व संवेदनशील-डेटा डिटेक्टर (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # HTTP प्रोटोकॉल वैलिडेटर (7), प्रत्येक को ऐप द्वारा दी गई सेटिंग्स चाहिए
├── session/               # सत्र सुरक्षा (2): session_guard, data_tamper
│                          #   Engine को बायपास कर सीधे मिडलवेयर के रूप में उपयोग
├── storage/               # स्टोरेज बैकएंड
│   ├── storage.go         #   Backend इंटरफ़ेस: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map, 30s में बैकग्राउंड सफ़ाई
│   ├── file.go            #   File: JSON पर्सिस्टेंस, Close पर flush
│   └── redis/             #   Redis: अलग सबमॉड्यूल, अपना go.mod
├── all/                   # 27 शून्य-कॉन्फ़िग डिटेक्टरों का एक-कॉल रजिस्ट्रेशन
├── pet/                   # प्रोजेक्ट शुभंकर: एम्बेडेड SVG + स्टार्टअप बैनर
├── docs/
│   ├── api.md             # API संदर्भ
│   ├── images/            # आर्किटेक्चर / फ़ीचर / जीवनचक्र SVG
│   ├── i18n/              # अनूदित दस्तावेज़ (12 भाषाएँ)
│   └── superpowers/       # डिज़ाइन स्पेक, कार्यान्वयन योजना, कोड समीक्षा रिपोर्ट
└── tests/                 # कवरेज रिपोर्ट
```

प्रत्येक डिटेक्टर पैकेज `xxx.go` के साथ `xxx_test.go` रखता है; `all` में इसके अतिरिक्त रिग्रेशन टेस्ट भी हैं।

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
    all.RegisterAll(e) // एक बार में 27 शून्य-कॉन्फ़िग डिटेक्टर रजिस्टर करता है

    // एकल डिटेक्शन
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("पता चला: %v, गंभीरता: %d\n", r.Detected, r.Severity)

    // संपूर्ण डिटेक्शन
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
            log.Printf("आक्रमण डिटेक्शन: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP वैलिडेटर कॉन्फ़िगरेशन

```go
// विधि सत्यापन
e.Register(&httpval.Method{})

// रिक्वेस्ट बॉडी आकार सीमा
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type व्हाइटलिस्ट
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin जाँच
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP ब्लैकलिस्ट (स्वतः ब्लॉक: 5 बार/60s → 15 मिनट का ब्लॉक)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// आक्रमण होने पर रिकॉर्ड करें
blocked, _ := bl.RecordAttack(clientIP)
```

### सत्र सुरक्षा कॉन्फ़िगरेशन

`session` पैकेज सीधे मिडलवेयर के रूप में उपयोग होता है, `Engine` से नहीं गुज़रता। स्टोरेज एप्लिकेशन को स्वयं देना होता है (डिफ़ॉल्ट रूप से मेमोरी कार्यान्वयन उपलब्ध है, जिसे Redis आदि से बदला जा सकता है):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // वैकल्पिक: दूसरे देश से लॉगिन पहचानने के लिए GeoIP जोड़ें

// लॉगिन सफल होने पर सत्र बाइंड करें (token आपके लॉगिन फ़्लो से बनता है)
// दूरस्थ लॉगिन डिटेक्शन: उपयोगकर्ता के पुराने सबनेट से तुलना करें, नया सबनेट दिखते ही अलर्ट
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // token बाइंड करें → IP सबनेट / UA / डिवाइस फ़िंगरप्रिंट
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// सुरक्षित रूट: हाईजैक या दूरस्थ लॉगिन पर सीधे 401 लौटाएँ
mux.Handle("/api/", tr.Guard(apiHandler))

// या केवल डिटेक्शन करें और निपटान स्वयं तय करें
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// लॉगआउट
tr.Revoke(token)
```

डेटा टैंपरिंग डिटेक्शन: क्लाइंट और सर्वर एक साझा कुंजी रखते हैं, क्लाइंट पैरामीटर पर सिग्नेचर करता है, सर्वर दोबारा गणना करके सत्यापित करता है:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // दूसरा पैरामीटर सिग्नेचर रीप्ले रोकता है, nil हो सकता है

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // क्लाइंट: पैरामीटर के साथ ही सबमिट करें

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` डिफ़ॉल्ट रूप से बंद है: `X-Forwarded-For` / `X-Real-IP` क्लाइंट द्वारा नियंत्रित हो सकते हैं, इसे केवल अपने रिवर्स प्रॉक्सी के पीछे ही चालू करें।
> `FailClosed` डिफ़ॉल्ट रूप से बंद है (स्टोरेज विफलता पर अनुमति, `IPBlacklist` के समान); सत्र-संवेदनशील कार्यों के लिए इसे चालू करने की सलाह दी जाती है।

### कस्टम डिटेक्टर

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "दुर्भावनापूर्ण सामग्री मिली",
    }
}

e.Register(&MyDetector{})
```

### शुभंकर

`pet` पैकेज Sentinel Gopher को कंपाइल समय पर `go:embed` के ज़रिए SVG के रूप में एम्बेड करता है — रनटाइम पर किसी फ़ाइल पर निर्भरता नहीं, कोई तीसरे पक्ष की निर्भरता नहीं जोड़ी जाती:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // स्टार्टअप बैनर: टर्मिनल के अनुकूल सादा टेक्स्ट
http.Handle("/pet.svg", pet.Handler()) // डिबग रूट: image/svg+xml के रूप में परोसा जाता है, एक दिन का कैश
svg := pet.SVG()                       // या कच्चे SVG बाइट्स लें
```

### संबंधित दस्तावेज़

- [API दस्तावेज़](api.md) — मुख्य प्रकार, Detector/Engine इंटरफ़ेस, स्टोरेज बैकएंड इंटरफ़ेस, HTTP वैलिडेटर
- [डिज़ाइन स्पेक](specs/2026-07-29-attack-detection-design.md) — पैकेज संरचना, डिटेक्टर सूची
- [कार्यान्वयन योजना](plans/2026-07-29-attack-detection-plan.md) — चरण-दर-चरण कार्य योजना और कार्यान्वयन विचलन
- [कोड समीक्षा रिपोर्ट](reports/2026-07-29-code-review-report.md) — Bug फिक्स, टेस्ट कवरेज, आर्किटेक्चर मूल्यांकन
- [कोड समीक्षा रिपोर्ट v2](reports/2026-07-29-code-review-report-v2.md) — दूसरा दौर: 4 मुद्दे फिक्स, 18 टेस्ट फ़ाइलें जोड़ी गईं

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
