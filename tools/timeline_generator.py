#!/usr/bin/env python3
"""
timeline_generator.py

evidence/ klasöründeki CSV log dosyalarını okur.
Timestamp sütununa göre kronolojik (eskiden yeniye) sıralar.
Source IP, User, Description alanlarını core/masker.py ile maskeler.
Çıktı: analysis/master_timeline.csv
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import pandas as pd
except ImportError:
    print("Hata: pandas yüklü değil. pip install pandas")
    sys.exit(1)

from core.masker import LabMasker


# Sütun eşleştirmeleri
TIMESTAMP_ALIASES = ("Timestamp", "timestamp", "TimeCreated", "time_created", "Date", "datetime")
SOURCE_IP_ALIASES = ("SourceIP", "Source IP", "source_ip", "IpAddress", "IP", "ClientAddress")
USER_ALIASES = ("User", "Username", "username", "TargetUserName", "UserName", "AccountName")
DESCRIPTION_ALIASES = ("Description", "description", "Status", "status", "Message", "Event")


def find_column(df: pd.DataFrame, aliases: tuple) -> str | None:
    """DataFrame'de eşleşen sütun adını döner."""
    cols = {c.lower(): c for c in df.columns}
    for a in aliases:
        if a.lower() in cols:
            return cols[a.lower()]
    return None


def safe_parse_datetime(series: pd.Series) -> pd.Series:
    """Tarih serisini parse eder, hatalı değerler NaT olur."""
    return pd.to_datetime(series, errors="coerce", utc=True)


def mask_value(value: str, masker: LabMasker, field_type: str) -> str:
    """Değeri alan türüne göre maskeler."""
    if pd.isna(value) or value is None:
        return ""
    val = str(value).strip()
    if not val:
        return ""
    if field_type == "ip":
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            return masker.mask_ip(val)
        return masker.mask_text(val)
    if field_type == "user":
        if val in ("-", "N/A", "SYSTEM", "ANONYMOUS LOGON"):
            return val
        return masker._mask_local_part(val)
    if field_type == "description":
        return masker.mask_text(val)
    return val


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Timeline oluşturucu (Pandas, KVKK maskeli)")
    parser.add_argument("-i", "--input", default="evidence", help="Log klasörü")
    parser.add_argument("-o", "--output", default="analysis/master_timeline.csv", help="Çıktı dosyası")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    evidence_path = Path(args.input)
    if not evidence_path.is_absolute():
        evidence_path = project_root / evidence_path

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path

    if not evidence_path.exists() or not evidence_path.is_dir():
        print(f"Hata: {evidence_path} bulunamadı veya klasör değil.")
        sys.exit(1)

    csv_files = [p for p in evidence_path.glob("**/*.csv") if "hash" not in p.name.lower() and "inventory" not in p.name.lower()]
    if not csv_files:
        print("Uyarı: evidence/ altında CSV dosyası bulunamadı.")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(columns=["DateTime", "EventSource", "EventID", "MaskedUser", "MaskedDescription"]).to_csv(
            output_path, index=False, encoding="utf-8"
        )
        print(f"Boş timeline oluşturuldu: {output_path}")
        return

    dfs = []
    for csv_path in csv_files:
        try:
            df = pd.read_csv(csv_path, encoding="utf-8")
            if df.empty:
                continue
            df["_EventSource"] = csv_path.name
            dfs.append(df)
        except (pd.errors.ParserError, OSError) as e:
            print(f"Uyarı: {csv_path} okunamadı: {e}", file=sys.stderr)

    if not dfs:
        print("Hata: Hiçbir CSV yüklenemedi.")
        sys.exit(1)

    combined = pd.concat(dfs, ignore_index=True)

    ts_col = find_column(combined, TIMESTAMP_ALIASES)
    if not ts_col:
        ts_col = combined.columns[0]

    combined["_DateTime"] = safe_parse_datetime(combined[ts_col])
    combined = combined.dropna(subset=["_DateTime"])
    combined = combined.sort_values("_DateTime", ascending=True)

    masker = LabMasker()

    ip_col = find_column(combined, SOURCE_IP_ALIASES)
    user_col = find_column(combined, USER_ALIASES)
    desc_col = find_column(combined, DESCRIPTION_ALIASES)

    result = pd.DataFrame()
    result["DateTime"] = combined["_DateTime"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    result["EventSource"] = combined["_EventSource"]

    eid_col = find_column(combined, ("EventID", "event_id", "EventCode", "Id"))
    result["EventID"] = (
        combined[eid_col].apply(lambda x: "" if pd.isna(x) else str(int(x)) if isinstance(x, (int, float)) and float(x) == int(float(x)) else str(x))
        if eid_col
        else ""
    )

    result["MaskedUser"] = (
        combined[user_col].apply(lambda x: mask_value(x, masker, "user"))
        if user_col
        else ""
    )

    desc_list = []
    if ip_col:
        desc_list.append(combined[ip_col].apply(lambda x: "SourceIP: " + mask_value(x, masker, "ip")))
    if desc_col:
        desc_list.append(combined[desc_col].apply(lambda x: mask_value(x, masker, "description")))
    if desc_list:
        result["MaskedDescription"] = desc_list[0].astype(str)
        for d in desc_list[1:]:
            result["MaskedDescription"] = result["MaskedDescription"] + " | " + d.astype(str)
    else:
        result["MaskedDescription"] = ""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    result[["DateTime", "EventSource", "EventID", "MaskedUser", "MaskedDescription"]].to_csv(
        output_path, index=False, encoding="utf-8"
    )

    print(f"Timeline kaydedildi: {output_path}")
    print(f"  {len(result)} olay (KVKK maskeli)")


if __name__ == "__main__":
    main()
