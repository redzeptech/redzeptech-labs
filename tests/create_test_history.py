"""Create test History SQLite for browser_parser and browser_artifact_parser."""
import sqlite3
from pathlib import Path

# Webkit: 13371336000000000 ≈ 2024-09-20 20:00:00 UTC
WEBKIT_TS = 13371336000000000

p = Path(__file__).parent.parent / "evidence" / "History_test.db"
p.parent.mkdir(parents=True, exist_ok=True)
conn = sqlite3.connect(str(p))
conn.execute("""CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY,
    url TEXT,
    title TEXT,
    visit_count INTEGER,
    last_visit_time INTEGER
)""")
# last_visit_time yoksa ekle (eski schema uyumluluğu)
try:
    conn.execute("ALTER TABLE urls ADD COLUMN last_visit_time INTEGER")
except sqlite3.OperationalError:
    pass
conn.execute(
    "INSERT OR REPLACE INTO urls VALUES (1, 'https://example.com/search?q=password&token=abc123', 'Example', 5, ?)",
    (WEBKIT_TS,),
)
conn.execute("INSERT OR REPLACE INTO urls VALUES (2, 'https://google.com/', 'Google', 10, ?)", (WEBKIT_TS - 1000000,))
conn.execute(
    "INSERT OR REPLACE INTO urls VALUES (3, 'https://github.com/user?tab=repositories', 'GitHub', 3, ?)",
    (WEBKIT_TS - 2000000,),
)
conn.commit()
conn.close()
print("Test History created:", p)
