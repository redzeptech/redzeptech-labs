# RedzepTech Labs — Agent Rehberi

Bu dosya AI asistanları ve geliştiriciler için proje kurallarını tanımlar.

---

## Proje Yapısı

```
redzeptech-labs/
├── core/           # Temel mantık (masker, vb.)
├── tools/          # DFIR araçları (CLI scriptler)
├── scripts/        # Yardımcı scriptler (veri üretimi, analiz)
├── labs/           # Lab senaryoları
├── evidence/       # Ham kanıtlar
├── analysis/       # İşlenmiş veri, timeline
├── reports/        # Raporlar
├── data/           # raw/, processed/
└── tests/          # Unit testler
```

---

## Maskeleme (KVKK)

- **core/masker.py** kullanılmalı — tüm hassas veri maskelemesi bu modülden.
- IPv4: `192.168.x.x` formatı
- E-posta: `u***r@domain.com` formatı
- URL sorgu parametreleri: `token`, `password`, `email` vb. → `***`
- Dosya yolu: `C:\Users\***\` (mask_path)

---

## Tarih Formatı

- **ISO 8601 UTC**: `%Y-%m-%dT%H:%M:%SZ` (örn. `2024-09-20T20:00:00Z`)
- Timeline, browser history ve diğer zaman damgaları bu formatta.

---

## Araçlar (tools/)

| Araç | Amaç |
|------|------|
| **browser_parser.py** | Chrome/Edge History → analysis/browser_history.csv (KVKK maskeli) |
| **hasher.py** | Dosya hash (MD5/SHA-256) → evidence/hash_inventory.csv |
| **timeline_generator.py** | evidence/ CSV'leri → analysis/master_timeline.csv |
| **reporter.py** | analysis/ → reports/case_report.md |

**Deprecated**: `browser_artifact_parser.py` — `browser_parser.py` kullanın.

---

## Testler

- `tests/test_masker.py` — LabMasker
- `tests/test_browser_parser.py` — browser_parser (Webkit timestamp, maskeleme)
- `python tests/test_*.py` ile çalıştır

---

## Dil ve Kodlama

- Docstring'ler Türkçe veya İngilizce olabilir.
- CLI çıktıları Türkçe tercih edilir.
- Python 3.10+ hedeflenir.
