#!/usr/bin/env python3
"""
browser_parser.py

Chrome/Edge History SQLite dosyasını analiz eder.
- urls tablosundan url, title, visit_count, last_visit_time çeker
- Webkit (Microseconds since 1601) zaman damgasını ISO 8601'e çevirir
- core/masker.py ile hassas veri maskeleme (token, password, email vb.)
- Başlıklardaki kişisel isimleri maskeler
"""

import csv
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker

# Webkit epoch: 1601-01-01 00:00:00 UTC
# Unix epoch: 1970-01-01 00:00:00 UTC
# Fark: 11644473600 saniye
WEBKIT_EPOCH_OFFSET = 11644473600

# Hassas sorgu parametreleri (case-insensitive)
SENSITIVE_PARAM_KEYS = frozenset(
    k.lower()
    for k in (
        "token",
        "password",
        "pass",
        "email",
        "user",
        "username",
        "session",
        "key",
        "secret",
        "auth",
        "api_key",
        "access_token",
        "refresh_token",
    )
)


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


def webkit_to_iso8601(webkit_us: int) -> str:
    """
    Chrome/Edge Webkit zaman damgasını (1601'den bu yana mikrosaniye)
    ISO 8601 formatına çevirir.
    """
    if webkit_us is None or webkit_us == 0:
        return ""
    try:
        unix_ts = (webkit_us / 1_000_000) - WEBKIT_EPOCH_OFFSET
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError):
        return ""


def mask_url_query_params(url: str, masker: LabMasker) -> str:
    """
    URL içindeki token, password, email vb. sorgu parametrelerini maskeler.
    Hassas parametrelerin değeri *** olur; diğerleri mask_text ile işlenir.
    """
    if not url or not isinstance(url, str):
        return url
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return masker.mask_text(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        masked_params = {}
        for k, v_list in params.items():
            key_lower = k.lower()
            if key_lower in SENSITIVE_PARAM_KEYS:
                masked_params[k] = ["***"]
            else:
                masked_params[k] = [masker.mask_text(str(v)) for v in v_list]
        masked_query = urlencode(masked_params, doseq=True)
        base_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            "",
            "",
        ))
        result = f"{base_url}?{masked_query}" if masked_query else base_url
        return masker.mask_text(result)
    except Exception:
        return masker.mask_text(url)


# Başlıkta maskelemeyecek yaygın kelimeler (marka, site vb.)
TITLE_BLOCKLIST = frozenset(
    w.lower()
    for w in (
        "Google", "Microsoft", "Chrome", "Edge", "Firefox", "Safari",
        "Windows", "Mac", "Linux", "Search", "Home", "Page", "Login",
        "Sign", "Settings", "Account", "Profile", "Dashboard", "Admin",
    )
)


def mask_title(title: str, masker: LabMasker) -> str:
    """
    Başlıktaki IP, e-posta ve kişisel isimleri maskeler.
    """
    if not title or not isinstance(title, str):
        return title
    result = masker.mask_text(title)

    def _replace_name(match):
        w1, w2 = match.group(1), match.group(2)
        if w1.lower() in TITLE_BLOCKLIST or w2.lower() in TITLE_BLOCKLIST:
            return match.group(0)
        return "*** ***"

    result = re.sub(
        r"\b([A-ZÇĞİÖŞÜ][a-zçğıöşü]+)\s+([A-ZÇĞİÖŞÜ][a-zçğıöşü]+)\b",
        _replace_name,
        result,
    )
    return result


def parse_history(history_path: Path, masker: LabMasker) -> list[dict]:
    """
    History SQLite dosyasından url, title, visit_count, last_visit_time çeker.
    URL ve title maskelenir.
    """
    if not history_path.exists():
        return []

    try:
        conn = sqlite3.connect(f"file:{history_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
        )
        rows = []
        for row in cur.fetchall():
            url = row["url"] or ""
            title = row["title"] or ""
            visit_count = row["visit_count"] or 0
            last_visit = row["last_visit_time"] or 0
            rows.append({
                "url": mask_url_query_params(url, masker),
                "title": mask_title(title, masker),
                "visit_count": visit_count,
                "last_visit_time": webkit_to_iso8601(last_visit),
            })
        conn.close()
        return rows
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
        print(f"Uyarı: {history_path} okunamadı: {e}", file=sys.stderr)
        return []


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Chrome/Edge History analizi (KVKK maskeli)"
    )
    parser.add_argument(
        "history_file",
        nargs="?",
        help="History dosya yolu (Chrome/Edge SQLite)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="analysis/browser_history.csv",
        help="Çıktı CSV (varsayılan: analysis/browser_history.csv)",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=500,
        help="Maksimum kayıt sayısı",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    masker = LabMasker()

    if args.history_file:
        history_path = Path(args.history_file)
        if not history_path.is_absolute():
            history_path = project_root / history_path
        paths_to_try = [(history_path, "Custom")]
    else:
        paths_to_try = [
            (p, "Chrome" if "Chrome" in str(p) else "Edge")
            for p in get_default_history_paths()
        ]

    all_rows = []
    for history_path, source in paths_to_try:
        if not history_path.exists():
            continue
        rows = parse_history(history_path, masker)
        for r in rows:
            r["source"] = source
        all_rows.extend(rows)

    rows = all_rows[: args.limit]

    if not rows:
        print("Hata: History dosyası bulunamadı veya okunamadı.")
        print("  Chrome/Edge kapalı olmalı. Veya: python browser_parser.py <path>")
        sys.exit(1)

    fieldnames = ["url", "title", "visit_count", "last_visit_time", "source"]

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"Rapor kaydedildi: {output_path}")
    print(f"  {len(rows)} URL (KVKK maskeli)")


if __name__ == "__main__":
    main()
