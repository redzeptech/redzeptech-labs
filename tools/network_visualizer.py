#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
network_visualizer.py

analysis/network_report.json ve PCAP dosyalarından IP'leri alır.
Ücretsiz ip-api.com ile dış IP'lerin ülke konumunu bulur.
Cartopy ile dünya haritası üzerinde bağlantıları gösterir.
Etiketlerde yerel ağ IP'leri @core/masker.py ile maskelenir.
Çıktı: analysis/network_map.png
"""

import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import mask_ip

# RFC1918 özel ağ aralıkları
RFC1918 = [
    (0x0A000000, 0x0AFFFFFF),   # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),   # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),   # 192.168.0.0/16
]


def _ip_to_int(ip: str) -> int | None:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except (ValueError, AttributeError):
        return None


def _is_private(ip: str) -> bool:
    n = _ip_to_int(ip)
    if n is None:
        return True
    for lo, hi in RFC1918:
        if lo <= n <= hi:
            return True
    return False


def _extract_external_ips_from_pcap(evidence_dir: Path) -> set[str]:
    """PCAP dosyalarından dış IP'leri çıkarır."""
    try:
        from scapy.all import rdpcap
    except ImportError:
        return set()

    external = set()
    for p in list(evidence_dir.glob("*.pcap")) + list(evidence_dir.glob("*.pcapng")):
        try:
            for pkt in rdpcap(str(p)):
                if pkt.haslayer("IP"):
                    ip_layer = pkt["IP"]
                    for attr in ("src", "dst"):
                        ip = getattr(ip_layer, attr, None)
                        if ip and ":" not in str(ip) and not _is_private(str(ip)):
                            external.add(str(ip))
        except Exception:
            pass
    return external


def _extract_ips_from_network_report(report_path: Path) -> tuple[set[str], set[str]]:
    """network_report.json'dan IP'leri okur. (masked, unmasked) - masked olanlar geolocate edilemez."""
    if not report_path.exists():
        return set(), set()
    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return set(), set()

    all_ips = set()
    for key in ("src", "dst"):
        for ip in data.get("ips", {}).get(key, []):
            if ip:
                all_ips.add(ip)

    # Maskeli (10.0.x.x) vs ham (1.2.3.4) ayır
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    unmasked = {ip for ip in all_ips if ip_pattern.match(ip) and "x" not in ip}
    masked = all_ips - unmasked
    return unmasked, masked


def _geolocate_ip(ip: str) -> dict | None:
    """ip-api.com ile ücretsiz geolocation (dakikada ~45 istek limiti)."""
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon,city"
        req = urllib.request.Request(url, headers={"User-Agent": "RedzepTech-Labs/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return {"lat": data["lat"], "lon": data["lon"], "country": data.get("country", ""), "city": data.get("city", "")}
    except Exception:
        pass
    return None


def _create_map_cartopy(geo_data: list[dict], output_path: Path) -> bool:
    """Cartopy ile dünya haritası oluşturur."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import cartopy.crs as ccrs
        import cartopy.feature as cfeature
    except ImportError as e:
        print(f"Uyarı: Cartopy yüklü değil ({e}). Alternatif deneniyor...")
        return False

    fig = plt.figure(figsize=(14, 8))
    ax = fig.add_subplot(1, 1, 1, projection=ccrs.PlateCarree())
    ax.set_global()
    ax.add_feature(cfeature.LAND, facecolor="#e8e8e8")
    ax.add_feature(cfeature.OCEAN, facecolor="#b8d4e8")
    ax.add_feature(cfeature.COASTLINE, linewidth=0.5)
    ax.add_feature(cfeature.BORDERS, linestyle=":", linewidth=0.3)
    ax.gridlines(draw_labels=True, dms=True, x_inline=False, y_inline=False, alpha=0.5)

    lats = [d["lat"] for d in geo_data]
    lons = [d["lon"] for d in geo_data]
    labels = [d["label"] for d in geo_data]

    ax.scatter(lons, lats, c="#c41e3a", s=80, marker="o", transform=ccrs.PlateCarree(), zorder=5, edgecolors="black", linewidths=1)
    for lon, lat, label in zip(lons, lats, labels):
        ax.text(lon + 1, lat + 1, label, fontsize=8, transform=ccrs.PlateCarree(), ha="left", va="bottom")

    plt.title("Ağ Trafiği — Dış IP Konumları (maskeli)", fontsize=12)
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    return True


def _create_map_plotly(geo_data: list[dict], output_path: Path) -> bool:
    """Plotly ile dünya haritası (cartopy yoksa fallback)."""
    try:
        import plotly.express as px
        import pandas as pd
    except ImportError:
        return False

    df = pd.DataFrame(geo_data)
    fig = px.scatter_geo(df, lat="lat", lon="lon", text="label", hover_name="label")
    fig.update_geos(showcountries=True, coastlinecolor="gray", landcolor="#e8e8e8", oceancolor="#b8d4e8")
    fig.update_traces(marker=dict(size=12, color="#c41e3a", line=dict(width=1, color="black")))
    fig.update_layout(title="Ağ Trafiği — Dış IP Konumları (maskeli)", height=500)

    try:
        fig.write_image(str(output_path))
        return True
    except Exception:
        fig.write_html(str(output_path.with_suffix(".html")))
        print(f"PNG için kaleido gerekli. HTML kaydedildi: {output_path.with_suffix('.html')}")
        return False


def run(project_root: Path, output_path: Path | None = None) -> Path | None:
    """Ana işlem."""
    report_path = project_root / "analysis" / "network_report.json"
    evidence_dir = project_root / "evidence"
    if output_path is None:
        output_path = project_root / "analysis" / "network_map.png"

    # 1. Ham dış IP'leri al (PCAP öncelikli)
    external_ips = _extract_external_ips_from_pcap(evidence_dir)
    if not external_ips:
        unmasked, _ = _extract_ips_from_network_report(report_path)
        external_ips = {ip for ip in unmasked if not _is_private(ip)}

    if not external_ips:
        print("Uyarı: Geolocate edilebilecek dış IP bulunamadı. PCAP veya network_report.json kontrol edin.")
        return None

    # 2. Geolocate (rate limit için kısa bekleme)
    geo_data = []
    for ip in sorted(external_ips):
        info = _geolocate_ip(ip)
        if info:
            geo_data.append({
                "lat": info["lat"],
                "lon": info["lon"],
                "label": f"{mask_ip(ip)} — {info.get('country', '')}",
            })
        time.sleep(0.15)  # ip-api.com rate limit

    if not geo_data:
        print("Uyarı: Hiçbir IP geolocate edilemedi.")
        return None

    # 3. Harita oluştur
    if _create_map_cartopy(geo_data, output_path):
        print(f"Harita kaydedildi: {output_path}")
        return output_path
    if _create_map_plotly(geo_data, output_path):
        print(f"Harita kaydedildi: {output_path}")
        return output_path

    print("Hata: Harita oluşturulamadı. pip install cartopy veya plotly kaleido deneyin.")
    return None


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Ağ trafiği harita görselleştirmesi")
    parser.add_argument("-o", "--output", default="analysis/network_map.png", help="Çıktı dosyası")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    out = Path(args.output)
    if not out.is_absolute():
        out = project_root / out

    run(project_root, output_path=out)


if __name__ == "__main__":
    main()
