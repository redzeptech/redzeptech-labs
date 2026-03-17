#!/usr/bin/env python3
"""
hasher.py

hashlib ile dosyaların MD5, SHA-1 ve SHA-256 değerlerini hesaplar.
Sonuçlar evidence/hash_inventory.csv dosyasına kaydedilir.
FilePath, core/masker.py ile maskelenir.
"""

import csv
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import mask_path


def compute_hashes(file_path: Path) -> dict[str, str]:
    """Dosyanın MD5, SHA-1, SHA-256 hashlerini hesaplar."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "MD5": md5.hexdigest(),
        "SHA-1": sha1.hexdigest(),
        "SHA-256": sha256.hexdigest(),
    }


def collect_files(target: Path) -> list[Path]:
    """Dosya veya dizindeki tüm dosyaları toplar (recursive)."""
    if target.is_file():
        return [target]
    if target.is_dir():
        return [p for p in target.rglob("*") if p.is_file()]
    return []


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Dosya hash hesaplama (MD5, SHA-1, SHA-256)")
    parser.add_argument("--path", required=True, help="Dosya veya dizin yolu")
    parser.add_argument("-o", "--output", default="evidence/hash_inventory.csv", help="Çıktı CSV")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Hata: {target} bulunamadı.")
        sys.exit(1)

    project_root = Path(__file__).resolve().parent.parent
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    files = collect_files(target)
    if not files:
        print("Hata: İşlenecek dosya bulunamadı.")
        sys.exit(1)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows = []

    for fp in sorted(files):
        try:
            hashes = compute_hashes(fp)
            masked_filepath = mask_path(str(fp))
            rows.append({
                "Timestamp": timestamp,
                "FilePath": masked_filepath,
                "MD5": hashes["MD5"],
                "SHA256": hashes["SHA-256"],
            })
        except (OSError, PermissionError):
            rows.append({
                "Timestamp": timestamp,
                "FilePath": mask_path(str(fp)),
                "MD5": "HATA",
                "SHA256": "HATA",
            })

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Timestamp", "FilePath", "MD5", "SHA256"])
        writer.writeheader()
        writer.writerows(rows)

    success_count = sum(1 for r in rows if r["MD5"] != "HATA")
    print(f"Hash envanteri kaydedildi: {mask_path(str(output_path))}")
    print(f"Toplam {len(rows)} dosyanın hash'i hesaplandı.")


if __name__ == "__main__":
    main()
