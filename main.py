#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py — Etkileşimli Menü

Konteyner veya yerel ortamda çalıştırıldığında araçları subprocess ile çağırır.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def run_script(script_path: str, args: list[str] | None = None) -> bool:
    """Script'i subprocess ile çalıştırır. Başarılı ise True döner."""
    cmd = [sys.executable, str(PROJECT_ROOT / script_path)]
    if args:
        cmd.extend(args)
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return result.returncode == 0


def show_menu() -> None:
    print("""
╔══════════════════════════════════════════════════════════════╗
║           RedzepTech Labs — Etkileşimli Menü                  ║
╠══════════════════════════════════════════════════════════════╣
║  1) Kanıt Hashlerini Hesapla (hasher.py)                     ║
║  2) Zaman Çizelgesi Oluştur (timeline_generator.py)         ║
║  3) Tarayıcı Geçmişini Analiz Et (browser_parser.py)         ║
║  4) Zararlı Yazılım Statik Analizi (static_analyzer.py)     ║
║  5) Ağ Trafiği Analizi (PCAP) (network_analyzer.py)         ║
║  6) Ağ Trafiği Görselleştirme (Harita) (network_visualizer)  ║
║  7) Final PDF Raporu Oluştur (reporter.py)                   ║
║  8) Hepsini Sırayla Yap ve Çık                               ║
║  0) Çıkış                                                    ║
╚══════════════════════════════════════════════════════════════╝
""")


def do_hash() -> None:
    print("\n>>> Kanıt Hashlerini Hesaplıyor...")
    run_script("tools/hasher.py", ["--path", "evidence/"])
    print()


def do_timeline() -> None:
    print("\n>>> Zaman Çizelgesi Oluşturuluyor...")
    run_script("tools/timeline_generator.py")
    print()


def do_browser() -> None:
    print("\n>>> Tarayıcı Geçmişi Analiz Ediliyor...")
    history_path = PROJECT_ROOT / "evidence" / "History_test.db"
    if history_path.exists():
        run_script("tools/browser_parser.py", [str(history_path)])
    else:
        run_script("tools/browser_parser.py")
    print()


def do_static_analyzer() -> None:
    print("\n>>> Zararlı Yazılım Statik Analizi...")
    pe_path = input("PE dosya yolu (Enter=evidence/ içinde .exe ara): ").strip()
    if not pe_path:
        exe_files = list(PROJECT_ROOT.glob("evidence/*.exe"))
        if exe_files:
            pe_path = str(exe_files[0])
            print(f"  Bulunan: {pe_path}")
        else:
            print("  Hata: evidence/ içinde .exe dosyası bulunamadı. Lütfen yol belirtin.")
            return
    run_script("tools/static_analyzer.py", [pe_path])
    print()


def do_network_analyzer() -> None:
    print("\n>>> Ağ Trafiği Analizi (PCAP)...")
    run_script("tools/network_analyzer.py", ["--path", "evidence/"])
    print()


def do_network_visualizer() -> None:
    print("\n>>> Ağ Trafiği Görselleştirme (Harita)...")
    run_script("tools/network_visualizer.py")
    print()


def do_report() -> None:
    print("\n>>> Final PDF Raporu Oluşturuluyor...")
    run_script("tools/reporter.py")
    print()


def do_all() -> None:
    print("\n>>> Tüm adımlar sırayla çalıştırılıyor...\n")
    do_hash()
    do_timeline()
    do_browser()
    exe_files = list(PROJECT_ROOT.glob("evidence/*.exe"))
    if exe_files:
        run_script("tools/static_analyzer.py", [str(exe_files[0])])
    do_network_analyzer()
    do_network_visualizer()
    do_report()
    print(">>> Tüm adımlar tamamlandı.")


def main() -> None:
    while True:
        show_menu()
        try:
            choice = input("Seçiminiz (0-8): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nÇıkılıyor.")
            sys.exit(0)

        if choice == "0":
            print("Çıkılıyor.")
            sys.exit(0)
        elif choice == "1":
            do_hash()
        elif choice == "2":
            do_timeline()
        elif choice == "3":
            do_browser()
        elif choice == "4":
            do_static_analyzer()
        elif choice == "5":
            do_network_analyzer()
        elif choice == "6":
            do_network_visualizer()
        elif choice == "7":
            do_report()
        elif choice == "8":
            do_all()
            sys.exit(0)
        else:
            print("Geçersiz seçim.")


if __name__ == "__main__":
    main()
