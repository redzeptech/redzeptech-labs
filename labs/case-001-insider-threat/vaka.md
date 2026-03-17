# Case 001 — Insider Threat (İç Tehdit)

## Senaryo

Bir şirket çalışanının **dışarıya veri sızdırdığından** şüpheleniliyor. Güvenlik ekibi, çalışanın bilgisayarından ve ağ loglarından toplanan kanıtları analiz etmek istiyor.

---

## Başlangıç Durumu

- `evidence/` klasöründe toplanan sistem logları (CSV formatında) mevcut
- Kanıtların bütünlüğünün doğrulanması gerekiyor
- Olayların kronolojik sırası çıkarılmalı
- Hassas veriler maskelenmiş bir rapor hazırlanmalı (KVKK uyumu)

---

## Görevler

| # | Görev | Açıklama |
|---|-------|----------|
| 1 | **Kanıtların hashini al** | `evidence/` altındaki dosyaların MD5, SHA-1, SHA-256 hashlerini hesapla |
| 2 | **Zaman çizelgesini oluştur** | CSV loglarından kronolojik timeline oluştur |
| 3 | **Maskelenmiş raporu hazırla** | Bulgular, hash değerleri ve zaman çizelgesi içeren vaka raporu üret |

---

## Beklenen Çıktılar

- `evidence/hash_log.txt` — Kanıt dosyalarının hash kaydı
- `analysis/master_timeline.csv` — Kronolojik olay listesi (KVKK maskeli)
- `reports/case_report.md` — Otomatik oluşturulmuş vaka raporu

---

## Notlar

- Tüm çıktılarda IP ve kullanıcı adları maskelenmiş olmalıdır
- Hash değerleri kanıt bütünlüğü için kritiktir
- Rapor, adli süreçte delil olarak kullanılabilir
