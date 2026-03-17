#!/bin/bash
# RedzepTech Labs — Tek Tuşla Başlatma
# Sistemi ayağa kaldırır, interaktif menüye bağlar, çıkışta temizler.

set -e
cd "$(dirname "$0")"

echo ">>> Sistem başlatılıyor (docker-compose up --build -d)..."
docker-compose up --build -d

echo ""
echo ">>> Interaktif menüye bağlanıyorsunuz. Çıkmak için 0 seçin veya Ctrl+C."
echo ""

# exec tamamlandığında (kullanıcı çıktığında) aşağıdaki satır çalışır
docker-compose exec -it lab_env python main.py || true

echo ""
echo ">>> Sistem kapatılıyor (docker-compose down)..."
docker-compose down

echo ">>> Tamamlandı."
