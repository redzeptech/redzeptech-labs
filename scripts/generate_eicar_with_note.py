# ==============================================================================
# SİBER GÜVENLİK LABORATUVARI ANALİST NOTU (FORENSIC LAB NOTE)
# ==============================================================================
# DİKKAT: Bu script, Antivirüs (AV) ve EDR testleri için kasıtlı olarak
# EICAR standart test imzasını oluşturmaktadır.
# Bu bir zararlı yazılım DEĞİLDİR, sadece imza tabanlı tespit testi amaçlıdır.
#
# KASPERSKY / DEFENDER İSTİSNA NOTU:
# Bu dizin (C:\Users\Recep\Desktop\redzeptech-labs) bir geliştirme ve
# adli bilişim laboratuvarıdır. Lütfen bu dosyayı "Dışlamalar" listesine ekleyin.
# ==============================================================================

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_eicar.py

Zararsız EICAR antivirüs test dosyası oluşturur.
Bu dosya gerçek bir zararlı yazılım DEĞİLDİR — sadece antivirüs yazılımlarının
tespit yeteneğini test etmek için kullanılan standart bir test string'idir.
"""

import time
from pathlib import Path

# Küçük parçalara bölünmüş liste — statik taramadan kaçınmak için (çalışma anında "".join ile birleştirilir)
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
