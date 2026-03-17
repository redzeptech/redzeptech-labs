#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
av_log_masker.py

Kaspersky ve Windows Event Log kayıtlarını tarar.
Proje yolu içeren satırlardaki kullanıcı isimlerini core/masker.py ile maskeler.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker, mask_path


# Varsayılan proje yolu (aranacak)
DEFAULT_PROJECT_PATH = r"C:\Users\Recep\Desktop\redzeptech-labs"
KASPERSKY_BASE = Path(r"C:\ProgramData\Kaspersky Lab")


def mask_line(line: str, masker: LabMasker) -> str:
    """Satırdaki yol ve kullanıcı adlarını maskeler."""
    result = mask_path(line)
    result = masker.mask_text(result)
    return result


def scan_kaspersky_logs(base_path: Path, project_path: str) -> list[tuple[str, str, str]]:
    """Kaspersky log dosyalarını tarar. (dosya, orijinal_satır, maskeli_satır) listesi döner."""
    if not base_path.exists():
        return []

    results = []
    masker = LabMasker()
    project_norm = project_path.replace("/", "\\").rstrip("\\")
    ext = (".log", ".txt", ".xml")

    for log_file in base_path.rglob("*"):
        if not log_file.is_file() or log_file.suffix.lower() not in ext:
            continue
        try:
            with open(log_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.rstrip("\n\r")
                    if project_norm in line or project_path in line:
                        masked = mask_line(line, masker)
                        results.append((str(log_file), line, masked))
        except (OSError, PermissionError):
            continue

    return results


def scan_event_viewer(project_path: str, limit: int = 500) -> list[tuple[str, str, str]]:
    """Windows Event Log'dan proje yolu içeren kayıtları tarar (wevtutil ile)."""
    if sys.platform != "win32":
        return []

    results = []
    masker = LabMasker()
    project_norm = project_path.replace("/", "\\")

    for log_name in ("Security", "Application", "System", "Windows PowerShell"):
        try:
            proc = subprocess.run(
                ["wevtutil", "qe", log_name, "/f:text", f"/c:{limit}", "/rd:true"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if proc.returncode != 0:
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if project_norm in line or project_path in line:
                    masked = mask_line(line, masker)
                    results.append((f"EventLog:{log_name}", line, masked))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue

    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="AV/Event log tarayıcı — proje yolu içeren satırlarda kullanıcı maskeleme")
    parser.add_argument("--project-path", default=DEFAULT_PROJECT_PATH, help="Aranacak proje yolu")
    parser.add_argument("--kaspersky", default=None, help="Kaspersky log dizini (varsayılan: C:\\ProgramData\\Kaspersky Lab)")
    parser.add_argument("--no-eventlog", action="store_true", help="Windows Event Log taramasını atla")
    parser.add_argument("-o", "--output", help="Maskeli sonuçları kaydet")
    parser.add_argument("-n", "--limit", type=int, default=500, help="Event Log kayıt limiti")
    args = parser.parse_args()

    project_path = args.project_path
    kaspersky_base = Path(args.kaspersky) if args.kaspersky else KASPERSKY_BASE

    all_results = []

    # Kaspersky logları
    k_results = scan_kaspersky_logs(kaspersky_base, project_path)
    all_results.extend(k_results)
    print(f"Kaspersky: {len(k_results)} eşleşme")

    # Windows Event Log
    if not args.no_eventlog:
        e_results = scan_event_viewer(project_path, args.limit)
        all_results.extend(e_results)
        print(f"Event Log: {len(e_results)} eşleşme")

    print(f"Toplam: {len(all_results)} satır (proje yolu içeren)")

    if all_results:
        lines = []
        for source, orig, masked in all_results:
            lines.append(f"# Kaynak: {source}")
            lines.append(f"Orijinal: {orig[:200]}{'...' if len(orig) > 200 else ''}")
            lines.append(f"Maskeli:  {masked[:200]}{'...' if len(masked) > 200 else ''}")
            lines.append("")

        output_text = "\n".join(lines)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(output_text)
            print(f"Sonuçlar kaydedildi: {out_path}")
        else:
            print("\n--- Örnek (ilk 5) ---")
            for source, orig, masked in all_results[:5]:
                print(f"[{source}]")
                print(f"  Orijinal: {orig[:120]}...")
                print(f"  Maskeli:  {masked[:120]}...")


if __name__ == "__main__":
    main()
