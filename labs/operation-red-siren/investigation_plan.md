# Operation Red-Siren — Olay Müdahale ve Analiz Planı

**Vaka Özeti:** AR-GE personelinin bilgisayarında olağan dışı aktiviteler. Güvenlik duvarı yurt dışındaki şüpheli IP'ye büyük veri transferi tespit etti. Personel bilgisayarın yavaşladığını ve dosyaların kendiliğinden oluştuğunu bildirdi.

**Kanıtlar (evidence/):**
- `sys_logs.csv` — Sistem olay günlükleri
- `browser_history.db` — Tarayıcı geçmişi
- `suspicious_tool.exe` — Masaüstünde bulunan isimsiz dosya
- `traffic_capture.pcap` — Olay anına ait ağ trafiği kaydı

---

## 1. Bütünlük (Evidence Integrity)

Tüm kanıtların hash değerlerini alarak kanıt zincirini koru.

```bash
python tools/hasher.py --path evidence/
```

**Çıktı:** `analysis/hash_inventory.csv` — Her dosya için SHA-256 hash değeri.

**Amaç:** Kanıtların değiştirilmediğini belgelemek; adli süreçte bütünlük kanıtı.

---

## 2. Zaman Akışı (Timeline)

Sistem loglarından olay anının kronolojisini çıkar.

```bash
python tools/timeline_generator.py
```

**Girdi:** `evidence/sys_logs.csv`  
**Çıktı:** `analysis/master_timeline.csv`

**Amaç:** Olayların ne zaman ve hangi sırada gerçekleştiğini belirlemek; şüpheli aktivite zaman dilimini tespit etmek.

---

## 3. Derin Analiz (Şüpheli Dosya)

Şüpheli EXE'yi statik analiz ve YARA ile tara.

```bash
# Statik analiz
python tools/static_analyzer.py evidence/suspicious_tool.exe

# YARA taraması
python tools/yara_scanner.py --path evidence/
```

**Çıktılar:**
- `analysis/malware_static_report.json` — Entropi, PE yapısı, importlar
- `analysis/yara_results.json` — YARA kural eşleşmeleri

**Amaç:** Dosyanın zararlı olup olmadığını, paketlenip paketlenmediğini ve hangi davranışları sergileyebileceğini anlamak.

---

## 4. Ağ İzleri (Network Mapping)

Verinin nereye gittiğini haritalandır.

```bash
# Ağ analizi
python tools/network_analyzer.py --path evidence/

# Intel kontrolü (tehdit listesi karşılaştırması)
python tools/intel_checker.py

# Coğrafi görselleştirme
python tools/network_visualizer.py
```

**Çıktılar:**
- `analysis/network_report.json` — IP, domain, MAC listeleri
- `analysis/intel_check_results.json` — YÜKSEK RİSK eşleşmeleri
- `analysis/network_map.png` — Dış IP konumları haritası

**Amaç:** Verinin hangi IP’lere gittiğini, bu IP’lerin tehdit listesinde olup olmadığını ve coğrafi konumlarını tespit etmek.

---

## 5. Kullanıcı İzleri (Browser Forensics)

Tarayıcıdan hangi zararlı veya şüpheli sitelere girildiğini bul.

```bash
python tools/browser_parser.py evidence/browser_history.db
```

**Çıktı:** `analysis/browser_history.csv` — Ziyaret edilen URL’ler, ziyaret sayıları, zaman damgaları.

**Amaç:** Personelin hangi siteleri ziyaret ettiğini, indirme yoluyla veya drive-by ile zararlı yazılıma maruz kalıp kalmadığını değerlendirmek.

---

## 6. Final Rapor

Tüm analiz sonuçlarını tek PDF’de birleştir.

```bash
python tools/reporter.py
```

**Çıktı:** `reports/Forensic_Report_Final.pdf` — Kanıt bütünlüğü, zaman çizelgesi, tarayıcı analizi, statik analiz, tehdit İstihbaratı ve ağ haritası dahil.

---

## Özet Akış

```
evidence/
├── sys_logs.csv
├── browser_history.db
├── suspicious_tool.exe
└── traffic_capture.pcap
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  1. hasher.py          → hash_inventory.csv                  │
│  2. timeline_generator → master_timeline.csv                 │
│  3. static_analyzer    → malware_static_report.json          │
│  3. yara_scanner       → yara_results.json                   │
│  4. network_analyzer   → network_report.json                 │
│  4. intel_checker      → intel_check_results.json            │
│  4. network_visualizer  → network_map.png                     │
│  5. browser_parser    → browser_history.csv                  │
│  6. reporter           → Forensic_Report_Final.pdf           │
└─────────────────────────────────────────────────────────────┘
```

---

## Notlar

- **Maskeleme:** Tüm analizlerde `@core/masker.py` ile PII maskeleme uygulanır.
- **Docker:** `docker-compose up` ile `main.py` menüsünden adımlar sırayla çalıştırılabilir.
- **Kanıt Yolu:** `evidence/` klasörü Docker’da anonymous volume olarak bağlanır; kanıtları buraya koyun.
