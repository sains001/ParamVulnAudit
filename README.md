# ParamVulnAudit

ParamVulnAudit adalah tool Python untuk audit indikasi awal kerentanan pada parameter URL. Tool ini mengirim probe ringan ke parameter yang ada di URL, lalu membandingkan respons untuk menemukan tanda-tanda umum seperti refleksi input, pesan error database, redirect eksternal, traversal marker, SSTI marker, dan perubahan respons yang mencurigakan.

Gunakan hanya pada aplikasi, domain, atau environment yang Anda miliki atau punya izin tertulis untuk diuji.

## Fitur

- Reflected XSS indicator
- SQL injection error indicator
- Open redirect indicator
- LFI/path traversal indicator
- Command injection marker indicator
- SSTI indicator
- Numeric tampering indicator
- Deteksi server error 5xx setelah input khusus
- Output teks atau JSON
- Bisa memilih parameter tertentu
- Rate limit sederhana dengan opsi `--delay`
- Tanpa dependency eksternal, cukup Python 3

## Batasan

Tool ini tidak membuktikan eksploitasi final. Hasilnya adalah indikasi awal yang perlu diverifikasi manual.

ParamVulnAudit tidak melakukan:

- Login otomatis
- Bypass autentikasi
- Crawling website
- Brute force
- Upload shell
- Eksploitasi aktif lanjutan
- Scan parameter POST/body JSON

Input utama harus berupa URL yang sudah memiliki query parameter, misalnya:

```text
https://example.com/page?id=1&q=test
```

## Struktur

```text
ParamVulnAudit/
├── param_vuln_audit.py
└── README.md
```

## Cara Menjalankan

Masuk ke folder tool:

```bash
cd /home/kali/ParamVulnAudit
```

Jalankan audit dasar:

```bash
python3 param_vuln_audit.py "https://example.com/page?id=1&q=test"
```

Jika URL tidak memakai `http://` atau `https://`, tool akan menambahkan `https://` secara otomatis.

## Contoh Penggunaan

Uji semua parameter yang ada di URL:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1&search=test&cat=book"
```

Uji satu parameter tertentu:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1&search=test" -p id
```

Uji beberapa parameter tertentu:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1&search=test&cat=book" -p id -p search
```

Output JSON:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1&search=test" --json
```

Atur jeda antar request:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1&search=test" --delay 1
```

Atur timeout:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1&search=test" --timeout 15
```

Batasi jumlah parameter yang diuji:

```bash
python3 param_vuln_audit.py "https://example.com/item?a=1&b=2&c=3" --max-params 2
```

## Opsi

| Opsi | Default | Keterangan |
| --- | --- | --- |
| `url` | wajib | URL lengkap dengan query parameter |
| `-p`, `--param` | kosong | Pilih parameter tertentu. Bisa dipakai berulang |
| `--max-params` | `10` | Batas maksimal parameter yang diuji |
| `--delay` | `0.5` | Jeda antar request dalam detik |
| `--timeout` | `10` | Timeout request dalam detik |
| `--json` | mati | Tampilkan hasil dalam format JSON |

## Jenis Probe

| Kategori | Tujuan |
| --- | --- |
| `Reflected XSS` | Mengecek apakah input terlihat kembali pada respons |
| `SQL Injection Error` | Mencari pesan error database setelah karakter khusus |
| `Open Redirect` | Mengecek apakah parameter mengontrol redirect eksternal |
| `LFI / Path Traversal` | Mencari marker file sistem setelah payload traversal |
| `Command Injection Indicator` | Mencari marker command probe pada respons |
| `SSTI Indicator` | Mengecek indikasi ekspresi template dievaluasi |
| `Numeric Tampering` | Membandingkan perubahan respons saat nilai diganti angka besar |
| `Server Error` | Melaporkan status 5xx yang muncul setelah probe |

## Severity

| Severity | Arti |
| --- | --- |
| `CRITICAL` | Indikasi kuat terhadap dampak tinggi, perlu verifikasi segera |
| `HIGH` | Indikasi kerentanan penting seperti SQL error, redirect, atau SSTI |
| `MEDIUM` | Risiko menengah seperti refleksi input atau server error |
| `INFO` | Sinyal awal yang perlu dicek manual, misalnya perubahan respons |

## Contoh Output

```text
Target             : https://example.com/item?id=1&q=test
Baseline HTTP      : 200
Parameter diuji    : id, q
Jumlah temuan      : 2

[HIGH] SQL Injection Error pada `id`
  Detail : Response memuat pesan error database setelah input karakter khusus.
  Bukti  : you have an error in your sql syntax
  URL    : https://example.com/item?id=%27%22%29%29%28&q=test

[MEDIUM] Reflected XSS pada `q`
  Detail : Payload terlihat kembali pada response. Periksa encoding output dan konteks HTML/JS.
  Bukti  : <pvaxss-1337>"'
  URL    : https://example.com/item?id=1&q=%3Cpvaxss-1337%3E%22%27
```

## Output JSON

Dengan opsi `--json`, hasil berisi:

- `target`: URL target
- `baseline_status`: status HTTP awal
- `tested_parameters`: daftar parameter yang diuji
- `findings`: daftar temuan
- `errors`: error ringan selama request

Contoh:

```bash
python3 param_vuln_audit.py "https://example.com/item?id=1" --json
```

## Alur Kerja yang Disarankan

1. Cari parameter terlebih dahulu dengan ParamFinderPy.
2. Pilih URL yang benar-benar memproses parameter.
3. Jalankan ParamVulnAudit pada URL tersebut.
4. Verifikasi manual setiap temuan.
5. Perbaiki validasi input, output encoding, query parameterization, dan kontrol redirect sesuai jenis temuan.

## Catatan Keamanan

Beberapa aplikasi bisa memberi false positive atau false negative. Contoh: input yang terlihat kembali belum tentu XSS jika sudah di-escape dengan benar, dan tidak adanya error SQL bukan berarti aman dari SQL injection. Gunakan hasil tool ini sebagai titik awal audit, bukan kesimpulan final.
