#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_case_data.py — Operation Red-Siren vaka kanıtları

evidence/sys_logs.csv         — Olay saatinde şüpheli giriş denemeleri
evidence/traffic_capture.pcap — Rusya/Kuzey Kore IP'sine giden trafik simülasyonu
evidence/suspicious_tool.exe  — Obfuscated EICAR (generate_eicar_obfuscated ile aynı)
"""

import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Obfuscated EICAR — generate_eicar_obfuscated.py ile aynı parçalar
_EICAR_PARTS = [
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


def _build_eicar() -> bytes:
    """EICAR test string'ini oluşturur."""
    return "".join(_EICAR_PARTS).encode("ascii")


def generate_sys_logs(evidence_dir: Path, event_hour: int = 14, event_minute: int = 30) -> Path:
    """Olay saatinde şüpheli giriş denemeleri (EventID 4625) yazar."""
    # Rusya tabanlı IP (şüpheli kaynak)
    russia_ips = ["185.220.101.1", "95.163.96.15", "185.86.151.11"]
    users = ["administrator", "admin", "root", "svc_backup", "guest", "system"]
    descriptions = [
        "Logon failure - Unknown user or bad password",
        "An account failed to log on",
        "Kerberos pre-authentication failed",
    ]

    today = datetime.now().replace(hour=event_hour, minute=event_minute, second=0, microsecond=0)
    rows = []
    for i in range(12):  # 14:30 civarında 12 başarısız giriş
        ts = today + timedelta(seconds=i * 5)
        rows.append({
            "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "EventID": 4625,
            "SourceIP": russia_ips[i % len(russia_ips)],
            "Username": users[i % len(users)],
            "Status": "Failed",
            "Description": descriptions[i % len(descriptions)],
        })

    out = evidence_dir / "sys_logs.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Timestamp", "EventID", "SourceIP", "Username", "Status", "Description"],
        )
        writer.writeheader()
        writer.writerows(rows)
    return out


def generate_traffic_pcap(evidence_dir: Path) -> Path:
    """Rusya/Kuzey Kore IP'sine giden trafik simüle eder."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        print("Uyarı: scapy yüklü değil. traffic_capture.pcap atlanıyor.")
        return None

    # İç ağ (personel bilgisayarı) -> Dış hedef (Rusya veya Kuzey Kore)
    src_ip = "192.168.1.100"
    dst_ip_ru = "95.163.96.1"      # Rusya
    dst_ip_nk = "175.45.176.1"     # Kuzey Kore — bu hedefe "veri sızıntısı" simüle ediyoruz

    packets = []
    payload = b"RED-SIREN-EXFIL-DATA-SIMULATION" * 100  # Büyük veri transferi simülasyonu

    for i in range(50):
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / IP(src=src_ip, dst=dst_ip_nk)
            / TCP(sport=50000 + i, dport=443, flags="PA")
            / Raw(load=payload[:1024])
        )
        packets.append(pkt)

    # Birkaç paket Rusya'ya da
    for i in range(10):
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
            / IP(src=src_ip, dst=dst_ip_ru)
            / TCP(sport=60000 + i, dport=443, flags="PA")
            / Raw(load=payload[:512])
        )
        packets.append(pkt)

    out = evidence_dir / "traffic_capture.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    return out


def generate_suspicious_tool(evidence_dir: Path) -> Path:
    """Obfuscated EICAR dosyasını suspicious_tool.exe olarak kopyalar."""
    out = evidence_dir / "suspicious_tool.exe"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as f:
        f.write(_build_eicar())
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Operation Red-Siren vaka kanıtları üret")
    parser.add_argument("--evidence", default="evidence", help="Kanıt klasörü")
    parser.add_argument("--hour", type=int, default=14, help="Olay saati")
    parser.add_argument("--minute", type=int, default=30, help="Olay dakikası")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    evidence_dir = project_root / args.evidence if not Path(args.evidence).is_absolute() else Path(args.evidence)

    print("Operation Red-Siren — Vaka kanıtları oluşturuluyor...")

    sys_logs = generate_sys_logs(evidence_dir, event_hour=args.hour, event_minute=args.minute)
    print(f"  {sys_logs}")

    pcap = generate_traffic_pcap(evidence_dir)
    if pcap:
        print(f"  {pcap}")

    exe = generate_suspicious_tool(evidence_dir)
    print(f"  {exe}")

    print("Tamamlandı.")


if __name__ == "__main__":
    main()
