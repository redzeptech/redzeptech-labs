#!/bin/bash
# Case 001 — Insider Threat (İç Tehdit) Lab Çözümü
# Kullanım: bash solution.sh (proje kök dizininden çalıştırın)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON=$(command -v python3 2>/dev/null || command -v python)

cd "$PROJECT_ROOT"

echo "=========================================="
echo "  Case 001 — Insider Threat Lab"
echo "=========================================="
echo ""

# Görev 1: Kanıtların hashini al
echo "[Görev 1] Kanıtların hashini alınıyor..."
$PYTHON tools/hasher.py --path evidence -o evidence/hash_inventory.csv
echo ""

# Görev 2: Zaman çizelgesini oluştur
echo "[Görev 2] Zaman çizelgesi oluşturuluyor..."
$PYTHON tools/timeline_generator.py -i evidence -o analysis/master_timeline.csv
echo ""

# Görev 3: Maskelenmiş raporu hazırla
echo "[Görev 3] Vaka raporu hazırlanıyor..."
$PYTHON tools/reporter.py -i analysis -o reports/case_report.md
echo ""

echo "=========================================="
echo "  Lab tamamlandı!"
echo "=========================================="
echo ""
echo "Çıktılar:"
echo "  • evidence/hash_log.txt"
echo "  • analysis/master_timeline.csv"
echo "  • reports/case_report.md"
echo ""
