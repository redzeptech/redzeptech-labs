#!/usr/bin/env python3
"""
browser_artifact_parser.py

DEPRECATED: tools/browser_parser.py kullanın.
- browser_parser: Webkit timestamp, core/masker, isim maskeleme, last_visit_time
- Bu script: Basit query string maskeleme (geriye dönük uyumluluk için korunuyor)

Chrome veya Edge 'History' SQLite dosyalarını analiz eder.
Ziyaret edilen URL'ler, başlıklar ve ziyaret sayılarını çıkarır.
Gizlilik: Sorgu parametreleri (query strings) maskelenir.
"""

import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def mask_query_string(url: str) -> str:
    """
    URL içindeki sorgu parametrelerinin değerlerini maskeler.
    Örnek: https://example.com/search?q=password&user=admin
         -> https://example.com/search?q=***&user=***
    """
    if not url or not isinstance(url, str):
        return url
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        params = parse_qs(parsed.query, keep_blank_values=True)
        masked_params = {k: ["***"] for k in params}
        masked_query = urlencode(masked_params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            masked_query,
            "",  # fragment - genelde gizlenir
        ))
    except Exception:
        return url


def get_default_history_paths() -> list[Path]:
    """Chrome ve Edge varsayılan History dosya yollarını döner."""
    paths = []
    if sys.platform == "win32":
        local = Path.home() / "AppData" / "Local"
        paths.extend([
            local / "Google" / "Chrome" / "User Data" / "Default" / "History",
            local / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
        ])
    elif sys.platform == "darwin":
        paths.extend([
            Path.home() / "Library" / "Application Support" / "Google Chrome" / "Default" / "History",
            Path.home() / "Library" / "Application Support" / "Microsoft Edge" / "Default" / "History",
        ])
    else:
        paths.extend([
            Path.home() / ".config" / "google-chrome" / "Default" / "History",
            Path.home() / ".config" / "microsoft-edge" / "Default" / "History",
        ])
    return paths


def parse_history(history_path: Path) -> list[dict]:
    """
    History SQLite dosyasından URL, title, visit_count çıkarır.
    URL'lerdeki query string'ler maskelenir.
    """
    if not history_path.exists():
        return []

    try:
        conn = sqlite3.connect(f"file:{history_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC"
        )
        rows = []
        for row in cur.fetchall():
            url = row["url"]
            title = row["title"] or ""
            visit_count = row["visit_count"] or 0
            rows.append({
                "url": mask_query_string(url),
                "title": title,
                "visit_count": visit_count,
            })
        conn.close()
        return rows
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
        print(f"Uyarı: {history_path} okunamadı: {e}", file=sys.stderr)
        return []


def main():
    import argparse
    import warnings

    warnings.warn(
        "browser_artifact_parser deprecated. Use: python tools/browser_parser.py",
        DeprecationWarning,
        stacklevel=1,
    )

    parser = argparse.ArgumentParser(description="Chrome/Edge History analizi (DEPRECATED - browser_parser kullanın)")
    parser.add_argument("history_file", nargs="?", help="History dosya yolu (opsiyonel)")
    parser.add_argument("-o", "--output", default="reports/browser_history.csv", help="Çıktı CSV")
    parser.add_argument("-n", "--limit", type=int, default=100, help="Maksimum kayıt sayısı")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent

    if args.history_file:
        paths = [Path(args.history_file)]
    else:
        paths = get_default_history_paths()

    all_rows = []
    for p in paths:
        if p.exists():
            rows = parse_history(p)
            source = "Chrome" if "Chrome" in str(p) else ("Edge" if "Edge" in str(p) else "Custom")
            for r in rows:
                r["_source"] = source
            all_rows.extend(rows)

    if not all_rows:
        print("Hata: History dosyası bulunamadı veya okunamadı.")
        print("  Chrome/Edge kapalı olmalı. Veya: python browser_artifact_parser.py <path>")
        sys.exit(1)

    # visit_count'a göre sırala (zaten parse_history'de)
    all_rows.sort(key=lambda r: r["visit_count"], reverse=True)
    all_rows = all_rows[: args.limit]

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    import csv
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "title", "visit_count", "source"])
        writer.writeheader()
        for r in all_rows:
            writer.writerow({
                "url": r["url"],
                "title": r["title"],
                "visit_count": r["visit_count"],
                "source": r.get("_source", ""),
            })

    print(f"Rapor kaydedildi: {output_path}")
    print(f"  {len(all_rows)} URL (query string'ler maskelenmiş)")


if __name__ == "__main__":
    main()
