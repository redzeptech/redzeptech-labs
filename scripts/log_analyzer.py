#!/usr/bin/env python3
"""
log_analyzer.py

data/raw/test_logs.csv dosyasını okur, hassas alanları maskeler,
data/processed/safe_logs.csv olarak kaydeder.
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker


def main():
    masker = LabMasker()

    input_path = Path(__file__).resolve().parent.parent / "data" / "raw" / "test_logs.csv"
    output_path = Path(__file__).resolve().parent.parent / "data" / "processed" / "safe_logs.csv"

    if not input_path.exists():
        print(f"Hata: {input_path} bulunamadı.")
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(input_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    masked_rows = []
    for row in rows:
        masked = dict(row)
        if "SourceIP" in masked and masked["SourceIP"]:
            masked["SourceIP"] = masker.mask_ip(masked["SourceIP"])
        if "Username" in masked and masked["Username"]:
            masked["Username"] = masker._mask_local_part(masked["Username"])  # u***r formatı
        masked_rows.append(masked)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(masked_rows)

    print("Analiz tamamlandı, veriler KVKK uyumlu hale getirildi")


if __name__ == "__main__":
    main()
