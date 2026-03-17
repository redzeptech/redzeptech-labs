# Intro Lab — Veri Maskeleme ve Log Analizi

## Lab Amacı

Bu laboratuvar, **Veri Maskeleme** ve **Log Analizi** temellerini uygulamalı olarak öğretir. Amaçlar:

- Hassas verilerin (IP, kullanıcı adı) nasıl maskeleneceğini öğrenmek
- KVKK uyumlu log işleme akışını deneyimlemek
- `core/masker.py` ve `log_analyzer.py` ile gerçek veri üzerinde çalışmak

---

## Adım Adım Kurulum ve Çalıştırma

### 1. Bağımlılıkları Yükle

```bash
pip install faker
```

### 2. Test Verisi Üret

Sahte Windows Güvenlik Logu oluşturur (100 satır, CSV):

```bash
python scripts/generate_test_data.py
```

Çıktı: `data/raw/test_logs.csv`

### 3. Log Analizi ve Maskeleme

Ham logları okuyup hassas alanları maskeler ve KVKK uyumlu dosyaya kaydeder:

```bash
python scripts/log_analyzer.py
```

Çıktı: `data/processed/safe_logs.csv`

### 4. Sonucu Kontrol Et

```bash
# Maskelenmiş dosyayı görüntüle (ilk 10 satır)
# Windows PowerShell:
Get-Content data/processed/safe_logs.csv -Head 10

# Linux/macOS:
head -10 data/processed/safe_logs.csv
```

---

## Maskeleme Öncesi ve Sonrası Veri Farkı

| Alan | Maskeleme Öncesi | Maskeleme Sonrası |
|------|------------------|-------------------|
| **SourceIP** | `183.214.39.114` | `183.214.x.x` |
| **SourceIP** | `33.232.50.155` | `33.232.x.x` |
| **SourceIP** | `103.173.150.154` | `103.173.x.x` |
| **Username** | `donaldgarcia` | `d***a` |
| **Username** | `robinsonwilliam` | `r***m` |
| **Username** | `shaneramirez` | `s***z` |
| **Username** | `joshua35` | `j***5` |

**Maskeleme kuralları:**
- **IP:** İlk iki oktet görünür, son iki oktet `x.x` ile değiştirilir
- **Kullanıcı adı:** İlk ve son karakter görünür, ortası `***` ile maskelenir

---

## Özet İş Akışı (Workflow)

| Adım | Komut | Açıklama |
|------|-------|----------|
| **1. Kur** | `bash setup.sh` | Kütüphaneleri yükle |
| **2. Üret** | `python scripts/generate_test_data.py` | Kirli veri oluştur |
| **3. Temizle** | `python scripts/log_analyzer.py` | Veriyi maskele |
| **4. İncele** | `data/processed/safe_logs.csv` | Güvenli verileri analiz et |

---

## Dosya Akışı

```
data/raw/test_logs.csv     →  log_analyzer.py  →  data/processed/safe_logs.csv
     (ham veri)                 (core/masker)           (KVKK uyumlu)
```
