#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
intel_checker.py

network_report.json veya PCAP dosyalarından dış IP'leri alır.
Bilinen zararlı IP listeleriyle karşılaştırır (simüle/opsiyonel).
Eşleşmeleri YÜKSEK RİSK olarak işaretleyip analysis/intel_check_results.json'a kaydeder.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import mask_ip

# RFC1918 özel ağ aralıkları (dış IP = bunların dışı)
RFC1918 = [
    (0x0A000000, 0x0AFFFFFF),   # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),   # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),   # 192.168.0.0/16
]


def _ip_to_int(ip: str) -> int | None:
    """IPv4 string'i integer'a çevirir."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except (ValueError, AttributeError):
        return None


def _is_private(ip: str) -> bool:
    """IP özel ağda mı?"""
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
                for layer in ("IP", "IPv6"):
                    if pkt.haslayer(layer):
                        ip_layer = pkt[layer]
                        for attr in ("src", "dst"):
                            ip = getattr(ip_layer, attr, None)
                            if ip and ":" not in str(ip) and not _is_private(str(ip)):
                                external.add(str(ip))
        except Exception:
            pass
    return external


def _extract_ips_from_network_report(report_path: Path) -> set[str]:
    """network_report.json'dan IP'leri okur — maskeli formatta (x.x.x.x) tam eşleşme zor)."""
    if not report_path.exists():
        return set()
    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return set()
    ips = set()
    for key in ("src", "dst"):
        for ip in data.get("ips", {}).get(key, []):
            if ip and "x.x" not in ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                ips.add(ip)
    return ips


def _load_threat_list(project_root: Path) -> set[str]:
    """Bilinen zararlı IP listesini yükler (simüle/opsiyonel)."""
    paths = [
        project_root / "data" / "threat_ips.txt",
        project_root / "data" / "known_malicious_ips.json",
    ]
    threat_ips = set()
    for p in paths:
        if not p.exists():
            continue
        try:
            if p.suffix == ".json":
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                    threat_ips.update(data.get("ips", data) if isinstance(data, dict) else data)
            else:
                with open(p, encoding="utf-8") as f:
                    for line in f:
                        ip = line.strip().split("#")[0].strip()
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                            threat_ips.add(ip)
        except Exception:
            pass
    return threat_ips


def run_check(project_root: Path) -> dict:
    """Intel kontrolü çalıştırır."""
    evidence_dir = project_root / "evidence"
    report_path = project_root / "analysis" / "network_report.json"

    external_ips = _extract_external_ips_from_pcap(evidence_dir)
    if not external_ips:
        report_ips = _extract_ips_from_network_report(report_path)
        external_ips = {ip for ip in report_ips if not _is_private(ip)}

    threat_ips = _load_threat_list(project_root)
    if not threat_ips:
        threat_ips = {"185.220.101.1", "45.142.212.61"}  # Simüle — örnek C2 IP'leri

    high_risk = []
    for ip in external_ips:
        if ip in threat_ips:
            high_risk.append({"ip": mask_ip(ip), "risk": "YÜKSEK RİSK", "source": "threat_list"})

    return {
        "external_ips_count": len(external_ips),
        "threat_list_count": len(threat_ips),
        "high_risk": high_risk,
        "high_risk_count": len(high_risk),
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Dış IP intel kontrolü")
    parser.add_argument("-o", "--output", default="analysis/intel_check_results.json", help="Çıktı JSON")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_path = project_root / args.output if not Path(args.output).is_absolute() else Path(args.output)

    result = run_check(project_root)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Intel kontrolü tamamlandı: {output_path}")
    print(f"  Dış IP: {result['external_ips_count']} | YÜKSEK RİSK: {result['high_risk_count']}")


if __name__ == "__main__":
    main()
