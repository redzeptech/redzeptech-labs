# Brute Force Analizi Senaryosu

## Senaryonun Amacı

Bu laboratuvar senaryosu, Windows Security loglarında **brute force (kaba kuvvet) giriş denemelerini** tespit etmeyi hedefler. Özellikle:

- **4624** — Başarılı giriş olaylarını
- **4625** — Hatalı giriş olaylarını

filtreleyerek, tekrarlayan başarısız denemelerden sonra başarılı giriş gibi şüpheli desenleri analiz etmenizi sağlar. Senaryo, olay müdahalesi (incident response) ve DFIR pratiği için tasarlanmıştır.

---

## evt_analyzer.py Nasıl Çalıştırılır?

### Gereksinimler

- Python 3.10+
- `utils/masker.py` (proje kökünde)

### Temel Kullanım

```powershell
# JSON log dosyası ile (ekrana maskeli çıktı)
python scripts/evt_analyzer.py scripts/sample_data/security_events.json

# JSON çıktı dosyasına kaydet
python scripts/evt_analyzer.py scripts/sample_data/security_events.json -o output.json

# CSV çıktı dosyasına kaydet
python scripts/evt_analyzer.py scripts/sample_data/security_events.json --csv-out output.csv
```

### Parametreler

| Parametre | Açıklama |
|-----------|----------|
| `log_file` | JSON veya CSV formatında log dosyası yolu |
| `-o`, `--output` | Sonuçları JSON dosyasına kaydet |
| `--csv-out` | Sonuçları CSV dosyasına kaydet |

---

## ⚠️ Önemli Not: KVKK Uyumu

**Tüm çıktılar (ekran ve dosya) otomatik olarak maskelenir.** Script, verileri ekrana basmadan veya dosyaya kaydetmeden önce `utils/masker.py` fonksiyonlarını kullanarak:

- **IP adreslerini** maskeler (son iki oktet `x.x` ile değiştirilir)
- **Kullanıcı adlarını** maskeler (ilk ve son harf görünür, ortası `*`)

Bu sayede raporlar KVKK (Kişisel Verilerin Korunması Kanunu) uyumlu kalır; gerçek IP veya kullanıcı adı hiçbir çıktıda görünmez.

---

## Örnek: Maskelenmiş Çıktı

| EventID | Açıklama | TargetUserName | IpAddress |
|---------|----------|----------------|-----------|
| 4624 | Başarılı Giriş | a***n | 192.168.x.x |
| 4625 | Hatalı Giriş | a***********r | 10.0.x.x |
| 4625 | Hatalı Giriş | a***n | 192.168.x.x |
| 4624 | Başarılı Giriş | u***1 | 172.16.x.x |
| 4625 | Hatalı Giriş | g***t | 203.0.x.x |
| 4624 | Başarılı Giriş | s********p | 10.0.x.x |

*Tablo: Tüm değerler maskelenmiş haldedir; orijinal veriler gösterilmez.*
