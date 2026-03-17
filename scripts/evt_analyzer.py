#!/usr/bin/env python3
"""
evt_analyzer.py

JSON veya CSV formatındaki Windows Security log dosyalarını okur.
4624 (Başarılı Giriş) ve 4625 (Hatalı Giriş) olaylarını filtreler.
Çıktıdan önce kullanıcı adları ve IP'ler masker.py ile maskelenir.
"""

import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.masker import mask_ip, mask_username, mask_path


EVENT_IDS = (4624, 4625)  # Başarılı Giriş, Hatalı Giriş

# Olası alan adları (farklı log formatları için)
IP_FIELDS = ("IpAddress", "ip_address", "SourceIp", "SourceIP", "source_ip", "ip", "ClientAddress")
USER_FIELDS = ("TargetUserName", "target_user_name", "UserName", "Username", "user_name", "AccountName", "account_name", "User")


def _mask_record(record: dict) -> dict:
    """Kayıttaki IP ve kullanıcı adı alanlarını maskeler."""
    masked = dict(record)
    for key, value in list(masked.items()):
        if value is None or not isinstance(value, str):
            continue
        key_lower = key.lower()
        if any(f.lower() == key_lower for f in IP_FIELDS) or "ip" in key_lower or "address" in key_lower:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(value).strip()):
                masked[key] = mask_ip(value)
        elif any(f.lower() == key_lower for f in USER_FIELDS) or "user" in key_lower or "account" in key_lower:
            if value and value not in ("-", "N/A", "SYSTEM", "ANONYMOUS LOGON"):
                masked[key] = mask_username(value)
    return masked


def _get_event_id(record: dict) -> int | None:
    """Kayıttan Event ID'yi çıkarır."""
    for field in ("EventID", "event_id", "EventCode", "event_code", "Id", "id"):
        val = record.get(field)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    return None


def _load_json(path: str) -> list[dict]:
    """JSON dosyasını okur. Tek obje veya liste olabilir."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # {"events": [...]} veya {"Records": [...]} gibi
        for key in ("events", "Records", "records", "data", "logs"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    return []


def _load_csv(path: str) -> list[dict]:
    """CSV dosyasını okur."""
    rows = []
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return rows


def analyze(log_path: str) -> list[dict]:
    """
    Log dosyasını okuyup 4624/4625 olaylarını filtreler.
    Dönen kayıtlar MASKELENMİŞ haldedir.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"Log dosyası bulunamadı: {log_path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        records = _load_json(str(path))
    elif suffix == ".csv":
        records = _load_csv(str(path))
    else:
        raise ValueError("Desteklenen formatlar: .json, .csv")

    filtered = []
    for r in records:
        eid = _get_event_id(r)
        if eid in EVENT_IDS:
            filtered.append(_mask_record(r))
    return filtered


def main():
    import argparse

    parser = argparse.ArgumentParser(description="4624/4625 log analizi (PII maskeli)")
    parser.add_argument("log_file", help="JSON veya CSV log dosyası")
    parser.add_argument("-o", "--output", help="Çıktı dosyası (JSON)")
    parser.add_argument("--csv-out", help="Çıktı dosyası (CSV)")
    args = parser.parse_args()

    try:
        results = analyze(args.log_file)
    except (FileNotFoundError, ValueError) as e:
        print(f"Hata: {mask_path(str(e))}", file=sys.stderr)
        sys.exit(1)

    # Ekrana bas (zaten maskeli)
    print(f"Toplam {len(results)} olay (4624/4625)")
    for i, r in enumerate(results[:20], 1):
        eid = _get_event_id(r)
        user = next((r.get(f) for f in USER_FIELDS if r.get(f)), "-")
        ip = next((r.get(f) for f in IP_FIELDS if r.get(f)), "-")
        print(f"  {i}. EventID={eid} User={user} IP={ip}")
    if len(results) > 20:
        print(f"  ... ve {len(results) - 20} olay daha")

    # Dosyaya kaydet (zaten maskeli)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\nJSON kaydedildi: {mask_path(args.output)}")

    if args.csv_out and results:
        headers = list(results[0].keys())
        with open(args.csv_out, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            w.writeheader()
            w.writerows(results)
        print(f"CSV kaydedildi: {mask_path(args.csv_out)}")


if __name__ == "__main__":
    main()
