# Security-Go कोड समीक्षा रिपोर्ट

**दिनांक**: 2026-07-29  
**प्रोजेक्ट**: github.com/erikwang2013/security-go  
**समीक्षा क्षेत्र**: 42 Go स्रोत फ़ाइलें, 8 पैकेज (security, all, data, file, httpval, injection, protocol, storage)  

---

## 1. टेस्ट परिणाम

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

- `go vet ./...` पास, कोई चेतावनी नहीं
- सभी टेस्ट पास
- **टेस्ट-रहित पैकेज**: `all` (केवल बाकी)

---

## 2. फिक्स किए गए Bug

### Bug #1 [महत्वपूर्ण] `storage/file.go:101` — JSON सीरियलाइज़ेशन त्रुटि चुपचाप अनदेखी

**समस्या**: `Close()` विधि में `data, _ := json.Marshal(out)` सीरियलाइज़ेशन त्रुटि को अनदेखा करता है। यदि JSON सीरियलाइज़ेशन विफल हो, तो `data` nil होता है और `os.WriteFile` खाली डेटा लिखता है, **जिससे पर्सिस्टेड डेटा पूरी तरह नष्ट हो जाता है**।

**फिक्स**: `json.Marshal` के त्रुटि रिटर्न की जाँच करें, विफलता पर तुरंत error लौटाएँ।

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

### Bug #2 [महत्वपूर्ण] `httpval/content_type.go:34` — खाली AllowList सभी Content-Type को पास करता है

**समस्या**: शर्त `if len(c.Allowed) == 0 || c.Allowed[mt]` का अर्थ है कि जब AllowList खाली हो, तो **सभी Content-Type पास हो जाते हैं**। सुरक्षित डिफ़ॉल्ट deny-all होना चाहिए।

**फिक्स**: `len(c.Allowed) == 0` शर्त हटाएँ — खाली AllowList अस्वीकृति शाखा में जाएगा।

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

### Bug #3 [मध्यम] `protocol/xxe.go:15` — `&[a-z]+;` सभी वैध HTML/XML एंटिटी से गलत मेल खाता है

**समस्या**: regex `(?i)&[a-z]+;` सभी मानक एंटिटी संदर्भों (`&amp;`, `&lt;`, `&gt;` आदि) से मेल खाएगा, जिससे किसी भी वैध HTML/XML वाले अनुरोध को XXE आक्रमण के रूप में गलत रिपोर्ट किया जाएगा।

**फिक्स**: मैचिंग को ज्ञात दुर्भावनापूर्ण प्रोटोकॉल प्रीफ़िक्स तक सीमित करें।

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. पाए गए गौण मुद्दे (अनफिक्स्ड, मूल्यांकन आवश्यक)

### मुद्दा #1: `all` पैकेज में टेस्ट कवरेज नहीं

`all/all.go` के `RegisterAll()` फ़ंक्शन के लिए कोई टेस्ट नहीं है। सभी पंजीकृत डिटेक्टरों के सामान्य रूप से कॉल होने की पुष्टि के लिए टेस्ट जोड़ना चाहिए।

### मुद्दा #2: `httpval` पैकेज टेस्ट जोड़े गए ✅ (हल)

`httpval/httpval_test.go` जोड़ा गया (32 टेस्ट केस), जो `BodySize` (7 टेस्ट), `ContentType` (7 टेस्ट), `CSRFOrigin` (8 टेस्ट), `IPBlacklist` (6 टेस्ट), `Method` (3 टेस्ट) कवर करता है। बाउंड्री वैल्यू, गलत इनपुट, खाली AllowList deny-all सत्यापन शामिल हैं।

### मुद्दा #3: `data/data_leak.go` क्रेडिट कार्ड regex बहुत व्यापक

`\b(?:\d[ -]*?){13,16}\b` किसी भी 13-16 अंकों की अनुक्रम से मेल खाएगा।

### मुद्दा #4: `storage/redis/` सबमॉड्यूल अधूरा

- `go.mod` में पैरेंट मॉड्यूल पर निर्भरता की घोषणा नहीं है
- `go.sum` फ़ाइल गायब है

### मुद्दा #5: protocol पैकेज और injection पैकेज की receiver शैली असंगत

- `injection` पैकेज पॉइंटर receiver उपयोग करता है: `func (d *XSS) Name() string`
- `protocol` पैकेज वैल्यू receiver उपयोग करता है: `func (d CORS) Name() string`

### मुद्दा #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` वैध HTML संख्यात्मक कैरेक्टर संदर्भों से मेल खाएगा

---

## 4. आर्किटेक्चर समग्र मूल्यांकन

| आयाम | स्कोर | विवरण |
|------|-------|--------|
| इंटरफ़ेस डिज़ाइन | ★★★★☆ | `Detector` इंटरफ़ेस + `Engine` ऑर्केस्ट्रेशन पैटर्न स्पष्ट |
| कोड एकरूपता | ★★★☆☆ | receiver शैली एकरूप नहीं |
| त्रुटि हैंडलिंग | ★★★☆☆ | फिक्स से पहले चुपचाप त्रुटि निगलना; फिक्स के बाद सुधार |
| टेस्ट कवरेज | ★★★★☆ | `httpval` टेस्ट जोड़े गए, `all` पैकेज अभी भी कमी |
| सुरक्षित डिफ़ॉल्ट | ★★★☆☆ | ContentType खाली AllowList समस्या फिक्स हो गई |
| डिटेक्शन सटीकता | ★★★☆☆ | कुछ regex में फ़ॉल्स-पॉज़िटिव जोखिम (xxe आंशिक रूप से फिक्स) |

---

## 5. सुझावित प्राथमिकताएँ

| प्राथमिकता | विषय |
|------------|------|
| ~~P0~~ | ~~`httpval` पैकेज टेस्ट जोड़ें~~ ✅ पूर्ण (32 टेस्ट, 5 डिटेक्टर) |
| P1 | `all` पैकेज टेस्ट जोड़ें |
| P1 | `storage/redis/` सबमॉड्यूल का go.mod फिक्स करें |
| P2 | receiver शैली को पॉइंटर receiver में एकरूप करें |
| P2 | क्रेडिट कार्ड/XSS regex फ़ॉल्स-पॉज़िटिव दर का मूल्यांकन करें |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
