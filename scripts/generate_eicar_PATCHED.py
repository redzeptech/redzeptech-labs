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
\"\"\"EICAR standart test dosyası oluşturucu - AV/EDR test amaçlı.\"\"\"

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def main():
    import sys
    from pathlib import Path
    out = Path(__file__).parent.parent / "evidence" / "eicar.com" if len(sys.argv) < 2 else Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(EICAR_STRING, encoding="ascii")
    print(f"EICAR test dosyası oluşturuldu: {out}")

if __name__ == "__main__":
    main()
