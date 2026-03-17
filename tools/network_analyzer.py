#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
network_analyzer.py

evidence/ altındaki .pcap/.pcapng dosyalarını scapy ile analiz eder.
- Benzersiz kaynak/hedef IP listesi
- DNS, HTTP, FTP'den domain çıkarımı
- core/masker.py ile IP ve MAC maskeleme
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker, mask_ip


def _get_ip_layer(pkt):
    """IP veya IPv6 katmanını döner."""
    if pkt.haslayer("IP"):
        return pkt["IP"]
    if pkt.haslayer("IPv6"):
        return pkt["IPv6"]
    return None


def analyze_pcap(pcap_path: Path, masker: LabMasker) -> dict:
    """PCAP/PCAPNG dosyasını analiz eder."""
    try:
        from scapy.all import rdpcap
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
    except ImportError:
        return {"error": "scapy yüklü değil. pip install scapy"}

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        return {"error": str(e)}

    src_ips = set()
    dst_ips = set()
    src_macs = set()
    dst_macs = set()
    domains = set()

    for pkt in packets:
        # IP
        ip_layer = _get_ip_layer(pkt)
        if ip_layer:
            src = getattr(ip_layer, "src", None)
            dst = getattr(ip_layer, "dst", None)
            if src:
                src_ips.add(str(src))
            if dst:
                dst_ips.add(str(dst))

        # MAC
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            if eth.src and eth.src != "00:00:00:00:00:00":
                src_macs.add(eth.src)
            if eth.dst and eth.dst != "ff:ff:ff:ff:ff:ff":
                dst_macs.add(eth.dst)

        # DNS
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if qname:
                domain = qname.decode("utf-8", errors="replace").rstrip(".")
                if domain and not domain.startswith("."):
                    domains.add(domain)
        if pkt.haslayer(DNSRR):
            for i in range(pkt[DNS].ancount):
                try:
                    rr = pkt[DNS].an[i]
                    if hasattr(rr, "rrname") and rr.rrname:
                        domain = rr.rrname.decode("utf-8", errors="replace").rstrip(".")
                        if domain:
                            domains.add(domain)
                except (IndexError, AttributeError):
                    pass

        # HTTP Host (TCP payload'dan)
        if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
            try:
                payload = bytes(pkt["Raw"].load)
                if b"Host:" in payload[:500] or b"GET " in payload[:20] or b"POST " in payload[:20]:
                    for line in payload.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            host = line[5:].strip().decode("utf-8", errors="replace").split(":")[0]
                            if host:
                                domains.add(host)
                            break
            except Exception:
                pass

        # FTP (USER, CWD, RETR vb. — domain genelde DNS'te; FTP sunucu IP'si)
        if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
            try:
                payload = bytes(pkt["Raw"].load).decode("utf-8", errors="replace")
                if "220" in payload[:50] or "USER " in payload[:20]:
                    if ip_layer and ip_layer.dst:
                        dst_ips.add(str(ip_layer.dst))
            except Exception:
                pass

    return {
        "src_ips": list(src_ips),
        "dst_ips": list(dst_ips),
        "src_macs": list(src_macs),
        "dst_macs": list(dst_macs),
        "domains": list(domains),
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="PCAP/PCAPNG ağ trafiği analizi")
    parser.add_argument("--path", default="evidence", help="Taranacak dizin")
    parser.add_argument("-o", "--output", default="analysis/network_report.json", help="Çıktı JSON")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    evidence_dir = project_root / args.path if not Path(args.path).is_absolute() else Path(args.path)
    output_path = project_root / args.output if not Path(args.output).is_absolute() else Path(args.output)

    if not evidence_dir.exists():
        print(f"Hata: {evidence_dir} bulunamadı.")
        sys.exit(1)

    pcap_files = list(evidence_dir.glob("*.pcap")) + list(evidence_dir.glob("*.pcapng"))
    if not pcap_files:
        print(f"Uyarı: {evidence_dir} içinde .pcap/.pcapng dosyası yok.")
        report = {"files": [], "summary": {"total_packets": 0}, "ips": {"src": [], "dst": []}, "macs": {"src": [], "dst": []}, "domains": []}
    else:
        masker = LabMasker()
        all_src_ips = set()
        all_dst_ips = set()
        all_src_macs = set()
        all_dst_macs = set()
        all_domains = set()

        for pf in pcap_files:
            result = analyze_pcap(pf, masker)
            if "error" in result:
                print(f"Uyarı: {pf.name}: {result['error']}")
                continue
            all_src_ips.update(result.get("src_ips", []))
            all_dst_ips.update(result.get("dst_ips", []))
            all_src_macs.update(result.get("src_macs", []))
            all_dst_macs.update(result.get("dst_macs", []))
            all_domains.update(result.get("domains", []))

        report = {
            "files": [str(p.name) for p in pcap_files],
            "ips": {
                "src": [mask_ip(ip) for ip in sorted(all_src_ips)],
                "dst": [mask_ip(ip) for ip in sorted(all_dst_ips)],
            },
            "macs": {
                "src": [masker.mask_mac(m) for m in sorted(all_src_macs)],
                "dst": [masker.mask_mac(m) for m in sorted(all_dst_macs)],
            },
            "domains": sorted(all_domains),
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Analiz tamamlandı: {output_path}")
    print(f"  Dosya: {len(pcap_files)} | IP: {len(report.get('ips', {}).get('src', [])) + len(report.get('ips', {}).get('dst', []))} | Domain: {len(report.get('domains', []))}")


if __name__ == "__main__":
    main()
