# Laporan Code Review Security-Go

**Tanggal**: 2026-07-29  
**Proyek**: github.com/erikwang2013/security-go  
**Ruang Lingkup Review**: 42 file sumber Go, 8 paket (security, all, data, file, httpval, injection, protocol, storage)

---

## 1. Hasil Pengujian

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

- `go vet ./...` lolos, tanpa peringatan
- Semua pengujian lolos
- **Paket tanpa pengujian**: `all` (satu-satunya yang tersisa)

---

## 2. Bug yang Telah Diperbaiki

### Bug #1 [Kritis] `storage/file.go:101` — Error serialisasi JSON diabaikan secara diam-diam

**Masalah**: Pada metode `Close()`, `data, _ := json.Marshal(out)` mengabaikan error serialisasi. Jika serialisasi JSON gagal, `data` bernilai nil dan `os.WriteFile` akan menulis data kosong, **menyebabkan seluruh data yang dipersistensikan hilang**.

**Perbaikan**: Periksa nilai error yang dikembalikan `json.Marshal`, dan segera kembalikan error jika gagal.

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

### Bug #2 [Kritis] `httpval/content_type.go:34` — AllowList kosong meloloskan semua Content-Type

**Masalah**: Kondisi `if len(c.Allowed) == 0 || c.Allowed[mt]` berarti ketika AllowList kosong, **semua Content-Type diloloskan**. Nilai default yang aman seharusnya deny-all.

**Perbaikan**: Hapus kondisi `len(c.Allowed) == 0`, AllowList kosong akan masuk ke cabang penolakan.

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

### Bug #3 [Sedang] `protocol/xxe.go:15` — `&[a-z]+;` salah mencocokkan semua entitas HTML/XML yang legal

**Masalah**: Regex `(?i)&[a-z]+;` akan mencocokkan semua referensi entitas standar (`&amp;`, `&lt;`, `&gt;`, dll.), sehingga permintaan apa pun yang mengandung HTML/XML legal dilaporkan salah sebagai serangan XXE.

**Perbaikan**: Persempit rentang pencocokan menjadi prefiks protokol berbahaya yang diketahui.

```go
// 修复前
regexp.MustCompile(`(?i)&[a-z]+;`),

// 修复后
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. Masalah Minor yang Ditemukan (Belum Diperbaiki, Perlu Evaluasi)

### Masalah #1: Paket `all` tanpa cakupan pengujian

Fungsi `RegisterAll()` pada `all/all.go` tidak memiliki pengujian apa pun. Sebaiknya ditambahkan pengujian untuk memverifikasi semua detektor yang terdaftar dapat dipanggil dengan normal.

### Masalah #2: Pengujian paket `httpval` telah dilengkapi ✅ (Selesai)

Telah ditambahkan `httpval/httpval_test.go` (32 kasus uji), mencakup `BodySize` (7 uji), `ContentType` (7 uji), `CSRFOrigin` (8 uji), `IPBlacklist` (6 uji), `Method` (3 uji). Termasuk verifikasi nilai batas, input error, dan deny-all untuk AllowList kosong.

### Masalah #3: Regex nomor kartu kredit `data/data_leak.go` terlalu luas

`\b(?:\d[ -]*?){13,16}\b` akan mencocokkan urutan angka 13-16 digit apa pun.

### Masalah #4: Submodul `storage/redis/` tidak lengkap

- `go.mod` tidak memiliki deklarasi dependensi ke modul induk
- File `go.sum` tidak ada

### Masalah #5: Gaya receiver paket protocol tidak konsisten dengan paket injection

- Paket `injection` menggunakan pointer receiver: `func (d *XSS) Name() string`
- Paket `protocol` menggunakan value receiver: `func (d CORS) Name() string`

### Masalah #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` akan mencocokkan referensi karakter numerik HTML yang legal

---

## 4. Evaluasi Arsitektur Keseluruhan

| Dimensi | Skor | Keterangan |
|------|------|------|
| Desain Antarmuka | ★★★★☆ | Pola antarmuka `Detector` + orkestrasi `Engine` jelas |
| Konsistensi Kode | ★★★☆☆ | Gaya receiver tidak seragam |
| Penanganan Error | ★★★☆☆ | Sebelum perbaikan ada error yang ditelan diam-diam; membaik setelah perbaikan |
| Cakupan Pengujian | ★★★★☆ | `httpval` telah dilengkapi pengujian, paket `all` masih kurang |
| Nilai Default Aman | ★★★☆☆ | Masalah AllowList kosong pada ContentType telah diperbaiki |
| Akurasi Deteksi | ★★★☆☆ | Sebagian regex berisiko salah positif (xxe telah diperbaiki sebagian) |

---

## 5. Prioritas yang Disarankan

| Prioritas | Hal |
|--------|------|
| ~~P0~~ | ~~Lengkapi pengujian paket `httpval`~~ ✅ Selesai (32 pengujian, 5 detektor) |
| P1 | Lengkapi pengujian paket `all` |
| P1 | Perbaiki go.mod submodul `storage/redis/` |
| P2 | Seragamkan gaya receiver menjadi pointer receiver |
| P2 | Evaluasi tingkat salah positif regex kartu kredit/XSS |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
