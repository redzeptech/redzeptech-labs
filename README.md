<p align="center">
  <img src="https://img.shields.io/badge/RedzepTech-Labs-1a1a2e?style=for-the-badge&logo=shield&logoColor=00d9ff" alt="RedzepTech Labs" />
</p>

<h1 align="center">🔬 RedzepTech Labs</h1>
<h3 align="center"><em>Advanced Digital Forensics & Malware Analysis Lab</em></h3>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/KVKK-Uyumlu-10B981?style=flat-square" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" />
</p>

---

## 📋 İçindekiler

- [Proje Özeti](#-proje-özeti)
- [Öne Çıkan Özellikler](#-öne-çıkan-özellikler)
- [Teknoloji Yığını](#-teknoloji-yığını)
- [Kurulum](#-kurulum)
- [Vaka Analizi: Operation Red-Siren](#-vaka-analizi-operation-red-siren)
- [KVKK & Gizlilik](#-kvkk--gizlilik)
- [Lisans](#-lisans)

---

## 🎯 Proje Özeti

**RedzepTech Labs**, dijital adli bilişim ve zararlı yazılım analizi için tasarlanmış, **KVKK uyumlu**, **Docker tabanlı** ve **otomatize edilmiş** bir laboratuvar ortamıdır.

Siber olay müdahale süreçlerinizi tek bir platformda toplayın: Kanıt bütünlüğünden zaman çizelgesi analizine, YARA taramasından ağ trafiği görselleştirmesine kadar tüm adımlar **tek komutla** veya **etkileşimli menü** üzerinden yürütülebilir. Tüm hassas veriler (IP, e-posta, kullanıcı adı, dosya yolu) **@core/masker.py** ile otomatik olarak maskelenir; raporlar KVKK standartlarına uygun şekilde üretilir.

> 💡 **Hedef:** Olay müdahale süreçlerini hızlandırmak, kanıt zincirini korumak ve adli raporlamayı standartlaştırmak.

---

## ✨ Öne Çıkan Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🎭 **Maskeleme Motoru** | `@core/masker.py` — IP, e-posta, MAC, dosya yolu ve metin içi PII otomatik maskelenir |
| 📅 **Zaman Çizelgesi Analizi** | Sistem loglarından kronolojik olay sırası; EventID 4624/4625 destekli |
| 🔍 **YARA Taraması** | Özelleştirilebilir kurallarla zararlı imza tespiti |
| 🌐 **Ağ Görselleştirme** | PCAP analizi, coğrafi harita (Cartopy/Plotly), tehdit intel kontrolü |
| 📄 **Otomatik PDF Raporlama** | Operation Red-Siren formatında yönetici özeti, kanıt bütünlüğü, tehdit analizi |

### Araçlar

```
tools/
├── hasher.py           # Kanıt hash hesaplama (MD5, SHA-256)
├── timeline_generator.py  # Zaman çizelgesi oluşturma
├── browser_parser.py  # Tarayıcı geçmişi analizi (SQLite)
├── static_analyzer.py # PE/entropi statik analiz
├── yara_scanner.py    # YARA kural motoru
├── network_analyzer.py   # PCAP analizi
├── network_visualizer.py # Coğrafi harita
├── intel_checker.py   # Tehdit IP karşılaştırması
└── reporter.py        # PDF rapor (Operation Red-Siren)
```

---

## 🛠 Teknoloji Yığını

| Katman | Teknoloji |
|--------|-----------|
| **Dil** | Python 3.10+ |
| **Veri Analizi** | Pandas |
| **Ağ Analizi** | Scapy |
| **PDF Rapor** | FPDF2 |
| **Zararlı İmza** | Yara-Python |
| **Harita** | Cartopy, Plotly, Folium |
| **Veritabanı** | SQLite (tarayıcı geçmişi) |
| **Ortam** | Docker, Docker Compose |

```yaml
# Örnek bağımlılıklar (requirements.txt)
pandas>=2.0.0
scapy>=2.5.0
fpdf2>=2.7.0
yara-python>=4.3.0
cartopy>=0.23.0
```

---

## 🚀 Kurulum

### Tek Komutla Başlatma (Önerilen)

```bash
./start_lab.sh
```

Bu komut:

1. `docker-compose up --build -d` ile ortamı ayağa kaldırır  
2. Etkileşimli menüye bağlanır (`main.py`)  
3. Çıkışta `docker-compose down` ile temizler  

### Manuel Kurulum

```bash
# Bağımlılıkları yükle
pip install -r requirements.txt

# Docker ile çalıştır
docker-compose up --build -d
docker-compose exec -it lab_env python main.py
```

### Yerel Çalıştırma

```bash
python main.py
```

---

## 📂 Vaka Analizi: Operation Red-Siren

**Operation Red-Siren**, AR-GE departmanında tespit edilen olağan dışı aktiviteleri inceleyen örnek bir senaryodur.

### Senaryo

| Öğe | Açıklama |
|-----|----------|
| **Olay** | Personel bilgisayarından yurt dışındaki şüpheli IP'ye büyük veri transferi |
| **İddia** | Bilgisayar yavaşladı; dosyalar kendiliğinden oluştu |
| **Kanıtlar** | `sys_logs.csv`, `browser_history.db`, `suspicious_tool.exe`, `traffic_capture.pcap` |

### Analiz Akışı

```
1. Bütünlük     → hasher.py
2. Zaman Akışı  → timeline_generator.py
3. Derin Analiz → static_analyzer.py, yara_scanner.py
4. Ağ İzleri    → network_analyzer.py, intel_checker.py, network_visualizer.py
5. Kullanıcı    → browser_parser.py
6. Rapor        → reporter.py → Forensic_Report_Final.pdf
```

### Vaka Verisi Üretme

```bash
python scripts/generate_case_data.py
```

Detaylı plan: [`labs/operation-red-siren/investigation_plan.md`](labs/operation-red-siren/investigation_plan.md)

---

## 🔒 KVKK & Gizlilik

Tüm hassas veriler **@core/masker.py** ile otomatik olarak maskelenir:

| Veri Türü | Maskeleme Örneği |
|-----------|------------------|
| IPv4 | `192.168.1.50` → `192.168.x.x` |
| E-posta | `user@domain.com` → `u***r@domain.com` |
| MAC | `aa:bb:cc:dd:ee:ff` → `aa:bb:cc:xx:xx:xx` |
| Dosya Yolu | `/Users/john/` → `/Users/***/` |
| Kullanıcı Adı | `administrator` → `a***r` |

- **Timeline**, **hash envanteri**, **PDF rapor** ve **ağ analizi** çıktılarında PII maskelenir.  
- Raporlarda yasal not: *"Bu rapordaki tüm PII verileri @core/masker.py ile KVKK standartlarında maskelenmiştir."*

---

## 📁 Proje Yapısı

```
redzeptech-labs/
├── core/
│   └── masker.py          # Maskeleme motoru
├── tools/                  # Analiz araçları
├── scripts/                # Yardımcı scriptler (generate_case_data, vb.)
├── evidence/               # Kanıtlar (Docker anonymous volume)
├── analysis/               # Analiz çıktıları
├── reports/                # PDF raporlar
├── labs/
│   └── operation-red-siren/
├── main.py                 # Etkileşimli menü
├── start_lab.sh            # Tek komutla başlatma
├── docker-compose.yml
└── requirements.txt
```

---

## 📜 Lisans

Bu proje **MIT Lisansı** altında lisanslanmıştır.

```
Copyright (c) 2026 RedzepTech Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

<p align="center">
  <strong>RedzepTech Labs</strong> — Advanced Digital Forensics & Malware Analysis Lab
</p>
