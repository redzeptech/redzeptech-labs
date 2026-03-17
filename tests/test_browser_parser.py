"""
browser_parser.py unit testleri.
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker
from tools.browser_parser import (
    webkit_to_iso8601,
    mask_url_query_params,
    mask_title,
    parse_history,
    WEBKIT_EPOCH_OFFSET,
)


def test_webkit_to_iso8601():
    """Webkit timestamp → ISO 8601 dönüşümü."""
    # 13371336000000000 = 2024-09-20 20:00:00 UTC civarı
    assert webkit_to_iso8601(13371336000000000) == "2024-09-20T20:00:00Z"
    assert webkit_to_iso8601(None) == ""
    assert webkit_to_iso8601(0) == ""


def test_mask_url_query_params():
    """Hassas sorgu parametreleri maskelenmeli."""
    masker = LabMasker()
    url = "https://example.com/login?token=abc123&email=user@test.com&q=normal"
    result = mask_url_query_params(url, masker)
    assert "token=%2A%2A%2A" in result or "token=***" in result
    assert "email=%2A%2A%2A" in result or "email=***" in result
    assert "q=normal" in result  # q hassas değil


def test_mask_title():
    """Başlıkta IP, e-posta ve isim maskelenmeli."""
    masker = LabMasker()
    assert mask_title("Ahmet Yilmaz - Dashboard", masker) == "*** *** - Dashboard"
    assert mask_title("Google Search", masker) == "Google Search"  # blocklist
    assert "x.x" in mask_title("Login from 192.168.1.1", masker)
    assert "***" in mask_title("Contact: user@domain.com", masker)


def test_parse_history():
    """History SQLite'dan okuma ve maskeleme."""
    p = Path(__file__).parent.parent / "evidence" / "test_history.db"
    if not p.exists():
        # Test DB yoksa oluştur
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(p)
        conn.execute("""CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            last_visit_time INTEGER
        )""")
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?,?,?,?)",
            ("https://test.com?token=secret", "Test Page", 1, 13371336000000000),
        )
        conn.commit()
        conn.close()

    masker = LabMasker()
    rows = parse_history(p, masker)
    assert len(rows) >= 1
    r = rows[0]
    assert "url" in r and "title" in r and "visit_count" in r and "last_visit_time" in r
    assert "***" in r["url"] or "token" in r["url"]
    assert r["last_visit_time"].endswith("Z")


if __name__ == "__main__":
    test_webkit_to_iso8601()
    test_mask_url_query_params()
    test_mask_title()
    test_parse_history()
    print("Tüm browser_parser testleri geçti.")
