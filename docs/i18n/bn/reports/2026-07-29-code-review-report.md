# Security-Go কোড রিভিউ রিপোর্ট

**তারিখ**: 2026-07-29  
**প্রকল্প**: github.com/erikwang2013/security-go  
**রিভিউ সুযোগ**: 42টি Go সোর্স ফাইল, 8টি প্যাকেজ (security, all, data, file, httpval, injection, protocol, storage)

---

## ১. টেস্ট ফলাফল

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

- `go vet ./...` পাস, কোনো ওয়ার্নিং নেই
- সব টেস্ট পাস
- **টেস্ট-বিহীন প্যাকেজ**: `all` (শুধু এটি বাকি)

---

## ২. মেরামত করা বাগসমূহ

### Bug #1 [গুরুত্বপূর্ণ] `storage/file.go:101` — JSON সিরিয়ালাইজেশন এরর নীরবে উপেক্ষিত

**সমস্যা**: `Close()` মেথডে `data, _ := json.Marshal(out)` সিরিয়ালাইজেশন এরর উপেক্ষা করত। JSON সিরিয়ালাইজেশন ব্যর্থ হলে `data` হবে nil, `os.WriteFile` ফাঁকা ডেটা লিখবে, **ফলে পার্সিস্টেন্স করা সব ডেটা হারিয়ে যাবে**।

**ফিক্স**: `json.Marshal`-এর এরর রিটার্ন ভ্যালু চেক করা, ব্যর্থ হলে সাথে সাথে error রিটার্ন করা।

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

### Bug #2 [গুরুত্বপূর্ণ] `httpval/content_type.go:34` — খালি AllowList সব Content-Type পাস করত

**সমস্যা**: `if len(c.Allowed) == 0 || c.Allowed[mt]` শর্তের অর্থ হলো, AllowList খালি থাকলে **সব Content-Type পাস হয়ে যায়**। নিরাপত্তার ডিফল্ট হওয়া উচিত deny-all।

**ফিক্স**: `len(c.Allowed) == 0` শর্তটি সরানো হয়েছে, খালি AllowList এখন রিজেক্ট ব্রাঞ্চে যায়।

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

### Bug #3 [মাঝারি] `protocol/xxe.go:15` — `&[a-z]+;` সব বৈধ HTML/XML এন্টিটির সাথে ভুলভাবে ম্যাচ করত

**সমস্যা**: রেজেক্স `(?i)&[a-z]+;` সব স্ট্যান্ডার্ড এন্টিটি রেফারেন্সের (`&amp;`, `&lt;`, `&gt;` ইত্যাদি) সাথে ম্যাচ করত, ফলে বৈধ HTML/XML ধারণকারী যেকোনো রিকোয়েস্ট ভুলভাবে XXE আক্রমণ হিসেবে রিপোর্ট হতো।

**ফিক্স**: ম্যাচিং পরিধি পরিচিত ম্যালিসিয়াস প্রোটোকল প্রিফিক্সে সীমাবদ্ধ করা হয়েছে।

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## ৩. পাওয়া গৌণ সমস্যা (মেরামত করা হয়নি, মূল্যায়ন প্রয়োজন)

### সমস্যা #1: `all` প্যাকেজে টেস্ট কভারেজ নেই

`all/all.go`-এর `RegisterAll()` ফাংশনের কোনো টেস্ট নেই। নিবন্ধিত সব ডিটেক্টর সঠিকভাবে কলযোগ্য কিনা যাচাই করার জন্য টেস্ট যোগ করা উচিত।

### সমস্যা #2: `httpval` প্যাকেজের টেস্ট যোগ হয়েছে ✅ (সমাধান করা হয়েছে)

`httpval/httpval_test.go` যোগ করা হয়েছে (32টি টেস্ট কেস), যা কভার করে `BodySize` (7টি টেস্ট), `ContentType` (7টি টেস্ট), `CSRFOrigin` (8টি টেস্ট), `IPBlacklist` (6টি টেস্ট), `Method` (3টি টেস্ট)। এর মধ্যে আছে বাউন্ডারি ভ্যালু, ভুল ইনপুট, খালি AllowList-এর deny-all যাচাই।

### সমস্যা #3: `data/data_leak.go`-এ ক্রেডিট কার্ড নম্বরের রেজেক্স অতিরিক্ত বিস্তৃত

`\b(?:\d[ -]*?){13,16}\b` যেকোনো 13-16 সংখ্যার ডিজিট সিকোয়েন্সের সাথে ম্যাচ করবে।

### সমস্যা #4: `storage/redis/` সাবমডিউল অসম্পূর্ণ

- `go.mod`-এ প্যারেন্ট মডিউলের ডিপেন্ডেন্সি ডিক্লারেশন নেই
- `go.sum` ফাইল নেই

### সমস্যা #5: protocol ও injection প্যাকেজের receiver স্টাইল অসামঞ্জস্যপূর্ণ

- `injection` প্যাকেজ পয়েন্টার রিসিভার ব্যবহার করে: `func (d *XSS) Name() string`
- `protocol` প্যাকেজ ভ্যালু রিসিভার ব্যবহার করে: `func (d CORS) Name() string`

### সমস্যা #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` বৈধ HTML সংখ্যাসূচক ক্যারেক্টার রেফারেন্সের সাথে ম্যাচ করবে

---

## ৪. আর্কিটেকচার সামগ্রিক মূল্যায়ন

| মাত্রা | স্কোর | বর্ণনা |
|--------|-------|--------|
| ইন্টারফেস ডিজাইন | ★★★★☆ | `Detector` ইন্টারফেস + `Engine` অর্কেস্ট্রেশন প্যাটার্ন পরিষ্কার |
| কোড ধারাবাহিকতা | ★★★☆☆ | receiver স্টাইল অসামঞ্জস্যপূর্ণ |
| এরর হ্যান্ডলিং | ★★★☆☆ | ফিক্সের আগে নীরব এরর গিলে ফেলা হতো; ফিক্সের পরে উন্নত |
| টেস্ট কভারেজ | ★★★★☆ | `httpval`-এ টেস্ট যোগ হয়েছে, `all` প্যাকেজে এখনো নেই |
| নিরাপত্তা ডিফল্ট মান | ★★★☆☆ | ContentType-এর খালি AllowList সমস্যা মেরামত করা হয়েছে |
| ডিটেকশন নির্ভুলতা | ★★★☆☆ | কিছু রেজেক্সে ভুল-পজিটিভ ঝুঁকি আছে (xxe আংশিকভাবে মেরামত হয়েছে) |

---

## ৫. প্রস্তাবিত অগ্রাধিকার

| অগ্রাধিকার | বিষয় |
|------------|-------|
| ~~P0~~ | ~~`httpval` প্যাকেজের টেস্ট যোগ করা~~ ✅ সম্পন্ন (32টি টেস্ট, 5টি ডিটেক্টর) |
| P1 | `all` প্যাকেজের টেস্ট যোগ করা |
| P1 | `storage/redis/` সাবমডিউলের go.mod মেরামত |
| P2 | receiver স্টাইল পয়েন্টার রিসিভারে একীভূত করা |
| P2 | ক্রেডিট কার্ড/XSS রেজেক্সের ভুল-পজিটিভ হার মূল্যায়ন |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
