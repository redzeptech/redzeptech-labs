#!/bin/bash
# RedzepTech Labs — Yönetim Script'i

set -e
cd "$(dirname "$0")"

show_menu() {
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║       RedzepTech Labs — Ana Menü         ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  1) Build   — İmajı oluştur              ║"
    echo "║  2) Analyze — Hasher, Timeline, Browser  ║"
    echo "║  3) Report  — PDF raporu üret            ║"
    echo "║  4) Clean   — analysis/ ve reports/ temizle║"
    echo "║  0) Çıkış                                ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
}

do_build() {
    echo ">>> Build: Docker imajı oluşturuluyor..."
    docker-compose build
    echo ">>> Build tamamlandı."
}

do_analyze() {
    echo ">>> Analyze: Hasher çalıştırılıyor..."
    python tools/hasher.py --path evidence/
    echo ""
    echo ">>> Analyze: Timeline oluşturuluyor..."
    python tools/timeline_generator.py
    echo ""
    echo ">>> Analyze: Browser parser çalıştırılıyor..."
    if [ ! -f "evidence/History_test.db" ]; then
        python tests/create_test_history.py 2>/dev/null || true
    fi
    if [ -f "evidence/History_test.db" ]; then
        python tools/browser_parser.py evidence/History_test.db
    else
        python tools/browser_parser.py 2>/dev/null || echo "  (History dosyası yok, atlanıyor)"
    fi
    echo ""
    echo ">>> Analyze tamamlandı."
}

do_report() {
    echo ">>> Report: PDF raporu oluşturuluyor..."
    python tools/reporter.py
    echo ">>> Report tamamlandı: reports/Forensic_Report_Final.pdf"
}

do_clean() {
    echo ">>> Clean: analysis/ ve reports/ temizleniyor..."
    rm -f analysis/*.csv analysis/*.json 2>/dev/null || true
    rm -f reports/*.pdf reports/*.csv reports/case_report.md 2>/dev/null || true
    echo ">>> Clean tamamlandı."
}

while true; do
    show_menu
    read -p "Seçiminiz (0-4): " choice
    case "$choice" in
        1) do_build ;;
        2) do_analyze ;;
        3) do_report ;;
        4) do_clean ;;
        0) echo "Çıkılıyor."; exit 0 ;;
        *) echo "Geçersiz seçim." ;;
    esac
done
