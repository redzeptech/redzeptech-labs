#!/bin/bash
# RedzepTech Labs — Proje Kurulum Scripti
# Kullanım: ./setup.sh veya bash setup.sh

set -e

echo "=========================================="
echo "  RedzepTech Labs — Kurulum"
echo "=========================================="
echo ""

# 1. Python kontrolü
echo "[1/4] Python kontrolü..."
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "HATA: Python bulunamadı. Lütfen Python 3.10+ yükleyin."
    exit 1
fi
PYTHON=$(command -v python3 2>/dev/null || command -v python)
echo "  Python: $($PYTHON --version)"
echo ""

# 2. Sanal ortam (opsiyonel)
echo "[2/4] Bağımlılıklar yükleniyor..."
$PYTHON -m pip install --upgrade pip -q
$PYTHON -m pip install -r requirements.txt -q
echo "  requirements.txt yüklendi."
echo ""

# 3. Klasör yapısı
echo "[3/4] Klasör yapısı oluşturuluyor..."
mkdir -p data/raw data/processed
echo "  data/raw, data/processed hazır."
echo ""

# 4. Test verisi ve analiz
echo "[4/4] Test verisi üretiliyor ve analiz çalıştırılıyor..."
$PYTHON scripts/generate_test_data.py -n 100
$PYTHON scripts/log_analyzer.py
echo ""

echo "=========================================="
echo "  Kurulum tamamlandı!"
echo "=========================================="
echo ""
echo "Sonraki adımlar:"
echo "  • Test verisi:  python scripts/generate_test_data.py"
echo "  • Log analizi:  python scripts/log_analyzer.py"
echo "  • EVT analizi:  python scripts/evt_analyzer.py data/raw/test_logs.csv -o output.json"
echo ""
echo "Lab rehberleri: labs/intro-lab/README.md"
echo ""
