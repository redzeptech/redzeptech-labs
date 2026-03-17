# RedzepTech Labs — DFIR Analiz Ortamı
FROM python:3.10-slim

WORKDIR /app

# PCAP işlemleri için tcpdump
RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

# pandas, fpdf2 ve diğer bağımlılıkları yükle
RUN pip install --no-cache-dir pandas fpdf2 faker scapy

# Proje dosyalarını kopyala (volume ile override edilecek dizinler hariç)
COPY . .

CMD ["python", "main.py"]
