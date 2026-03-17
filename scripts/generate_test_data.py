#!/usr/bin/env python3
"""
generate_test_data.py

Faker kütüphanesi ile sahte Windows Güvenlik Logu (CSV) üretir.
Sütunlar: Timestamp, EventID, SourceIP, Username, Status
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from faker import Faker
except ImportError:
    print("Faker yüklü değil. Kurulum: pip install faker")
    sys.exit(1)


def generate_security_logs(count: int = 100, seed: int | None = 42) -> list[dict]:
    """Sahte Windows Güvenlik Log kayıtları üretir."""
    fake = Faker()
    if seed is not None:
        Faker.seed(seed)

    records = []
    for _ in range(count):
        event_id = fake.random_element([4624, 4625])  # Başarılı / Hatalı giriş
        status = "Success" if event_id == 4624 else "Failed"
        records.append({
            "Timestamp": fake.date_time_this_year().strftime("%Y-%m-%d %H:%M:%S"),
            "EventID": event_id,
            "SourceIP": fake.ipv4(),
            "Username": fake.user_name(),
            "Status": status,
        })
    return records


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sahte Windows Güvenlik Logu üret")
    parser.add_argument("-n", "--count", type=int, default=100, help="Satır sayısı")
    parser.add_argument("-o", "--output", default="data/raw/test_logs.csv", help="Çıktı dosyası")
    parser.add_argument("--no-seed", action="store_true", help="Seed kullanma")
    args = parser.parse_args()

    records = generate_security_logs(count=args.count, seed=None if args.no_seed else 42)

    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = Path(__file__).resolve().parent.parent / out_path

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Timestamp", "EventID", "SourceIP", "Username", "Status"])
        writer.writeheader()
        writer.writerows(records)

    print(f"Oluşturuldu: {out_path} ({len(records)} satır)")


if __name__ == "__main__":
    main()
