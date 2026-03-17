# EICAR Dosyası ile Statik Analiz Testi

Bu yönerge, `evidence/suspicious_file.exe` (EICAR test dosyası) ile `static_analyzer.py`'nin nasıl test edileceğini açıklar.

---

## 0. generate_eicar.py Script'i

`scripts/generate_eicar.py` dosyası yoksa aşağıdaki içerikle oluşturun:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zararsız EICAR antivirüs test dosyası oluşturur."""

from pathlib import Path

EICAR_STRING = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def main():
    project_root = Path(__file__).resolve().parent.parent
    output_path = project_root / "evidence" / "suspicious_file.exe"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="ascii") as f:
        f.write(EICAR_STRING)
    print(f"EICAR test dosyası oluşturuldu: {output_path}")

if __name__ == "__main__":
    main()
```

---

## 1. EICAR Test Dosyası Oluşturma

```bash
python scripts/generate_eicar.py
```

**Çıktı:** `evidence/suspicious_file.exe` oluşturulur.

> **Not:** EICAR dosyası gerçek bir zararlı yazılım değildir. Antivirüs yazılımlarının tespit yeteneğini test etmek için kullanılan standart bir ASCII string'idir. `.exe` uzantısına rağmen geçerli bir PE dosyası değildir.

---

## 2. Statik Analiz Çalıştırma

```bash
python tools/static_analyzer.py evidence/suspicious_file.exe
```

**Beklenen davranış:**
- **Entropi:** Düşük (ASCII metin olduğu için ~4–5 civarı)
- **packed_guess:** "Normal"
- **strings_sample:** EICAR string'i ve benzeri kısa metinler görünür
- **pe_analysis:** `"error"` anahtarı ile PE parse hatası (geçerli PE olmadığı için)

---

## 3. Rapor Kontrolü

Analiz sonucu `analysis/malware_static_report.json` dosyasına kaydedilir:

```bash
# JSON içeriğini görüntüle
cat analysis/malware_static_report.json
# veya Windows'ta:
type analysis\malware_static_report.json
```

---

## 4. PDF Raporuna Dahil Etme

Statik analiz tamamlandıktan sonra PDF raporu oluşturulduğunda, "Zararlı Yazılım Ön İnceleme" bölümünde bu sonuçlar yer alır:

```bash
python tools/reporter.py
```

---

## 5. Ana Menü Üzerinden

```bash
python main.py
```

Menüden **4) Zararlı Yazılım Statik Analizi** seçin. PE dosya yolu sorulduğunda `evidence/suspicious_file.exe` yazın veya Enter'a basın (evidence/ içinde .exe ara).

---

## Özet Akış

```
scripts/generate_eicar.py  →  evidence/suspicious_file.exe
                                    ↓
tools/static_analyzer.py  →  analysis/malware_static_report.json
                                    ↓
tools/reporter.py         →  reports/Forensic_Report_Final.pdf (Zararlı Yazılım Ön İnceleme bölümü)
```
