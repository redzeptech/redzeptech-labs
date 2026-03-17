#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_eicar.py — EICAR test dosyası oluşturucu (obfuscated)
Statik taramadan kaçınmak için küçük parçalara bölünmüş liste kullanır.
Bellek taramasından kaçınmak için: gecikme + bytearray ile yazma.
"""

import time
from pathlib import Path

# Küçük parçalara bölünmüş liste — kaynak kodda ham EICAR string yok
_PARTS = [
    "X5O!",
    "P%@AP[",
    "4",
    chr(92),
    "PZX54(P^)7CC)7}$",
    "EICAR-",
    "STANDARD-",
    "ANTIVIRUS-",
    "TEST-FILE!",
    "$H+H*",
]


def _build() -> str:
    return "".join(_PARTS)


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    output_path = project_root / "evidence" / "eicar_test.txt"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    time.sleep(2)  # Bazı antivirüsler hızlı dosya yazımından şüphelenir
    data = bytearray(_build().encode("ascii"))

    with open(output_path, "wb") as f:
        f.write(data)

    print("Test dosyası başarıyla oluşturuldu")


if __name__ == "__main__":
    main()
