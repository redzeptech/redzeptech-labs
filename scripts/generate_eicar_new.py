#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_eicar.py

Zararsız EICAR antivirüs test dosyası oluşturur.
Bu dosya gerçek bir zararlı yazılım DEĞİLDİR — sadece antivirüs yazılımlarının
tespit yeteneğini test etmek için kullanılan standart bir test string'idir.
"""

from pathlib import Path

# EICAR Standard Antivirus Test File — zararsız test string'i
EICAR_STRING = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    output_path = project_root / "evidence" / "suspicious_file.exe"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="ascii") as f:
        f.write(EICAR_STRING)

    print(f"EICAR test dosyası oluşturuldu: {output_path}")
    print("  (Bu dosya zararsızdır — antivirüs testi için kullanılır)")


if __name__ == "__main__":
    main()
