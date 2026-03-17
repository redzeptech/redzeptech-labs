#!/usr/bin/env python3
"""
generate_mock_logs.py

Test için sahte Windows Security logları üretir.
Rastgele IP ve kullanıcı adları içeren CSV formatında çıktı verir.
evt_analyzer.py ile test edilmek üzere tasarlanmıştır.
"""

import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.masker import mask_path


# Yaygın kullanıcı adı önekleri/sonekleri
USER_PREFIXES = ("admin", "user", "svc", "backup", "test", "guest", "service", "app", "db", "web")
USER_SUFFIXES = ("01", "02", "admin", "backup", "test", "prod", "dev", "sys", "root", "")


def random_ip() -> str:
    """Rastgele geçerli IPv4 adresi üretir."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_username() -> str:
    """Rastgele kullanıcı adı üretir."""
    prefix = random.choice(USER_PREFIXES)
    suffix = random.choice(USER_SUFFIXES)
    if suffix:
        return f"{prefix}_{suffix}" if random.random() > 0.3 else f"{prefix}{suffix}"
    return prefix


def random_timestamp(days_back: int = 30) -> str:
    """Rastgele ISO formatında zaman damgası."""
    base = datetime.now(timezone.utc) - timedelta(days=random.randint(0, days_back))
    delta = timedelta(
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return (base + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_mock_logs(
    count: int = 50,
    success_ratio: float = 0.3,
    seed: int | None = 42,
) -> list[dict]:
    """
    Sahte Windows Security log kayıtları üretir.

    Args:
        count: Üretilecek kayıt sayısı
        success_ratio: 4624 (başarılı) oranı (0-1)
        seed: Tekrarlanabilirlik için seed

    Returns:
        EventID, TargetUserName, IpAddress, TimeCreated içeren dict listesi
    """
    if seed is not None:
        random.seed(seed)

    records = []
    for _ in range(count):
        event_id = 4624 if random.random() < success_ratio else 4625
        records.append({
            "EventID": event_id,
            "TargetUserName": random_username(),
            "IpAddress": random_ip(),
            "TimeCreated": random_timestamp(),
        })
    return records


def write_csv(records: list[dict], output_path: str) -> None:
    """Kayıtları CSV dosyasına yazar."""
    if not records:
        return
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sahte Windows Security logları üret (CSV)")
    parser.add_argument("-o", "--output", default="tests/mock_security_logs.csv",
                        help="Çıktı CSV dosyası")
    parser.add_argument("-n", "--count", type=int, default=50,
                        help="Kayıt sayısı")
    parser.add_argument("--success-ratio", type=float, default=0.3,
                        help="4624 oranı (0-1, varsayılan 0.3)")
    parser.add_argument("--no-seed", action="store_true",
                        help="Seed kullanma (her çalıştırmada farklı)")
    args = parser.parse_args()

    records = generate_mock_logs(
        count=args.count,
        success_ratio=args.success_ratio,
        seed=None if args.no_seed else 42,
    )

    # Çıktı yolu: mutlak değilse proje köküne göre
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = Path(__file__).resolve().parent.parent / out_path
    write_csv(records, str(out_path))

    success = sum(1 for r in records if r["EventID"] == 4624)
    failed = len(records) - success
    print(f"Oluşturuldu: {mask_path(str(out_path))}")
    print(f"  Toplam: {len(records)} kayıt (4624: {success}, 4625: {failed})")


if __name__ == "__main__":
    main()
