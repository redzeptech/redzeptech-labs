# Case 001 — Insider Threat

İç tehdit senaryosu: Veri sızıntısı şüphesi.

## Dosyalar

| Dosya | Açıklama |
|-------|----------|
| [vaka.md](vaka.md) | Senaryo, görevler ve beklenen çıktılar |
| [solution.sh](solution.sh) | Lab çözüm komutları |

## Hızlı Başlangıç

```bash
# Proje kökünden çalıştırın
bash labs/case-001-insider-threat/solution.sh
```

## Manuel Adımlar

1. `python tools/hasher.py evidence -o evidence/hash_log.txt`
2. `python tools/timeline_generator.py -i evidence -o analysis/master_timeline.csv`
3. `python tools/reporter.py -i analysis -o reports/case_report.md`
