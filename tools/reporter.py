#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporter.py

Dijital Adli Bilişim Analiz Raporu oluşturur (PDF).
- Kanıt Bütünlüğü: evidence/hash_inventory.csv
- Zaman Çizelgesi Özeti: analysis/master_timeline.csv (son 10 olay)
- Tarayıcı Analizi: analysis/browser_history.csv (en çok ziyaret edilen 5 site)
"""

import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _find_unicode_font() -> str | None:
    """Türkçe karakter destekleyen sistem fontu arar."""
    candidates = []
    if sys.platform == "win32":
        windir = os.environ.get("WINDIR", "C:\\Windows")
        candidates = [
            Path(windir) / "Fonts" / "arial.ttf",
            Path(windir) / "Fonts" / "Arial.ttf",
        ]
    elif sys.platform == "darwin":
        candidates = [
            Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
            Path("/Library/Fonts/Arial.ttf"),
        ]
    else:
        candidates = [
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
        ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


def _load_hash_inventory(project_root: Path) -> list[dict]:
    """evidence/hash_inventory.csv veya analysis/hash_inventory.csv okur."""
    for subpath in ("evidence/hash_inventory.csv", "analysis/hash_inventory.csv"):
        p = project_root / subpath
        if p.exists():
            rows = []
            with open(p, encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    rows.append(dict(row))
            return rows
    return []


def _load_timeline(project_root: Path, limit: int = 10) -> list[dict]:
    """analysis/master_timeline.csv son N olayı okur."""
    p = project_root / "analysis" / "master_timeline.csv"
    if not p.exists():
        return []
    rows = []
    with open(p, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(dict(row))
    return rows[-limit:] if len(rows) > limit else rows


def _load_static_analysis(project_root: Path) -> dict | None:
    """analysis/malware_static_report.json okur."""
    p = project_root / "analysis" / "malware_static_report.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _load_intel_check_results(project_root: Path) -> dict | None:
    """analysis/intel_check_results.json okur (intel_checker çıktısı)."""
    p = project_root / "analysis" / "intel_check_results.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _load_yara_results(project_root: Path) -> dict | None:
    """analysis/yara_results.json okur."""
    p = project_root / "analysis" / "yara_results.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _load_browser_history(project_root: Path, limit: int = 5) -> list[dict]:
    """analysis/browser_history.csv en çok ziyaret edilen N siteyi okur."""
    p = project_root / "analysis" / "browser_history.csv"
    if not p.exists():
        return []
    rows = []
    with open(p, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(dict(row))
    rows.sort(key=lambda r: int(r.get("visit_count", 0) or 0), reverse=True)
    return rows[:limit]


def _generate_vaka_no() -> str:
    """Otomatik vaka numarası üretir."""
    return f"VK-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"


def _build_executive_summary(
    yara_results: dict | None,
    static_analysis: dict | None,
    intel_results: dict | None,
    network_map_exists: bool,
) -> str:
    """Analiz sonuçlarına göre yönetici özeti oluşturur."""
    malware_detected = False
    data_exfil = False

    if yara_results and yara_results.get("matches"):
        malware_detected = True
    if static_analysis:
        entropy = static_analysis.get("entropy", 0)
        if isinstance(entropy, (int, float)) and entropy > 7.0:
            malware_detected = True
        if static_analysis.get("packed_guess", "").lower() in ("paketli", "packed", "yüksek"):
            malware_detected = True
    if intel_results and intel_results.get("high_risk_count", 0) > 0:
        data_exfil = True
    if network_map_exists:
        data_exfil = True

    if malware_detected and data_exfil:
        return (
            "Analiz sonuçlarına göre zararlı yazılım tespiti yapılmış ve veri sızıntısı bulguları mevcuttur. "
            "YARA taramasında eşleşmeler tespit edilmiş, statik analizde yüksek entropi ve paketlenme belirtileri "
            "gözlemlenmiştir. Ağ trafiği analizi yurt dışındaki şüpheli IP'lere bağlantıları ortaya koymuştur. "
            "Öneri: Olay müdahale protokolü devreye alınmalı, etkilenen sistem izole edilmeli ve derin inceleme yapılmalıdır."
        )
    if malware_detected:
        return (
            "Analiz sonuçlarına göre zararlı yazılım tespiti yapılmıştır. YARA veya statik analizde şüpheli imzalar "
            "veya yüksek entropi gözlemlenmiştir. Veri sızıntısı kanıtı sınırlıdır. Öneri: Şüpheli dosyalar karantinaya "
            "alınmalı ve detaylı davranış analizi yapılmalıdır."
        )
    if data_exfil:
        return (
            "Analiz sonuçlarına göre veri sızıntısı bulguları mevcuttur. Ağ trafiği yurt dışındaki IP'lere bağlantı "
            "göstermektedir. Zararlı yazılım imzası tespit edilmemiştir. Öneri: Ağ izolasyonu ve log incelemesi önerilir."
        )
    return (
        "Analiz tamamlanmış olup, YARA veya statik analizde zararlı imza tespit edilmemiş, veri sızıntısı kanıtı "
        "sınırlıdır. Mevcut kanıtlar rutin aktivite göstermektedir. Öneri: Periyodik izleme sürdürülmelidir."
    )


def generate_pdf_report(project_root: Path, output_path: Path) -> None:
    """Operation Red-Siren — Büyük Vaka PDF raporu oluşturur."""
    from fpdf import FPDF

    font_path = _find_unicode_font()
    hash_rows = _load_hash_inventory(project_root)
    timeline_rows = _load_timeline(project_root, limit=100)
    static_analysis = _load_static_analysis(project_root)
    intel_results = _load_intel_check_results(project_root)
    yara_results = _load_yara_results(project_root)
    network_map_path = project_root / "analysis" / "network_map.png"
    network_map_exists = network_map_path.exists()

    exec_summary = _build_executive_summary(
        yara_results, static_analysis, intel_results, network_map_exists
    )

    # En kritik 5 olay: EventID 4625 (başarısız giriş) öncelikli, yoksa son 5
    critical = [r for r in timeline_rows if str(r.get("EventID", "")) == "4625"]
    if len(critical) < 5:
        critical = (critical + [r for r in timeline_rows if r not in critical])[:5]
    else:
        critical = critical[:5]

    class ForensicPDF(FPDF):
        def __init__(self, font_path: str | None, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._font_ok = False
            if font_path:
                try:
                    self.add_font("UnicodeFont", "", font_path)
                    self._font_ok = True
                except Exception:
                    pass

        def header(self):
            if self._font_ok:
                self.set_font("UnicodeFont", "", 10)
            else:
                self.set_font("Helvetica", "", 10)
            self.set_text_color(128, 128, 128)
            self.cell(0, 8, "Operation Red-Siren — Gizli", new_x="LMARGIN", new_y="NEXT", align="C")
            self.ln(2)

        def footer(self):
            self.set_y(-20)
            if self._font_ok:
                self.set_font("UnicodeFont", "", 8)
            else:
                self.set_font("Helvetica", "", 8)
            self.set_text_color(100, 100, 100)
            self.multi_cell(0, 5, "Bu rapordaki tüm PII verileri @core/masker.py ile KVKK standartlarında maskelenmiştir.", align="C")

    pdf = ForensicPDF(font_path=font_path)
    pdf.set_auto_page_break(auto=True, margin=25)
    pdf.add_page()

    if pdf._font_ok:
        pdf.set_font("UnicodeFont", "", 12)
    else:
        pdf.set_font("Helvetica", "", 12)

    # ——— KAPAK SAYFASI ———
    pdf.set_font_size(10)
    pdf.set_text_color(180, 0, 0)
    pdf.cell(0, 8, "GIZLI", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)

    pdf.set_font_size(10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, "[Şirket Logosu Placeholder]", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.rect(75, pdf.get_y() + 2, 60, 50)
    pdf.set_y(pdf.get_y() + 55)
    pdf.ln(8)

    pdf.set_font_size(18)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 12, "Büyük Vaka: Operation Red-Siren", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)
    pdf.set_font_size(14)
    pdf.cell(0, 10, "Dijital Adli Bilişim Analiz Raporu", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(8)
    pdf.set_font_size(12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 8, "Vaka Numarası: RED-2026-001", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 8, f"Tarih: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(20)

    # ——— YONETICI OZETI ———
    pdf.add_page()
    pdf.set_font_size(14)
    pdf.cell(0, 10, "Yönetici Özeti", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font_size(10)
    pdf.ln(2)
    pdf.multi_cell(0, 5, exec_summary)
    pdf.ln(8)

    # ——— KANIT BUTUNLUGU (Tablo: MD5, SHA256) ———
    pdf.set_font_size(14)
    pdf.cell(0, 10, "1. Kanıt Bütünlüğü", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font_size(10)
    pdf.ln(2)

    if hash_rows:
        col_w = (60, 65, 65)
        headers = ("FilePath", "MD5", "SHA256")
        pdf.set_font_size(8)
        for h, w in zip(headers, col_w):
            pdf.cell(w, 6, str(h)[:25], border=1)
        pdf.ln()
        for row in hash_rows:
            pdf.cell(col_w[0], 6, str(row.get("FilePath", ""))[:25], border=1)
            pdf.cell(col_w[1], 6, str(row.get("MD5", ""))[:32], border=1)
            pdf.cell(col_w[2], 6, str(row.get("SHA256", ""))[:32], border=1)
            pdf.ln()
        pdf.ln(4)
    else:
        pdf.cell(0, 6, "(Hash envanteri bulunamadı. tools/hasher.py çalıştırın.)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ——— ZAMAN CIZELGESI (En kritik 5 olay) ———
    pdf.set_font_size(14)
    pdf.cell(0, 10, "2. Zaman Çizelgesi (En Kritik 5 Olay)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font_size(10)
    pdf.ln(2)

    if critical:
        for i, row in enumerate(critical, 1):
            dt = row.get("DateTime", "")
            eid = row.get("EventID", "")
            user = row.get("MaskedUser", "")
            desc = str(row.get("MaskedDescription", ""))[:55]
            pdf.set_font_size(8)
            pdf.cell(0, 5, f"{i}. {dt} | EventID:{eid} | {user} | {desc}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
    else:
        pdf.cell(0, 6, "(Zaman çizelgesi bulunamadı. tools/timeline_generator.py çalıştırın.)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ——— TEHDIT ANALIZI (YARA + Statik) ———
    pdf.set_font_size(14)
    pdf.cell(0, 10, "3. Tehdit Analizi", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font_size(10)
    pdf.ln(2)

    if yara_results and yara_results.get("matches"):
        pdf.set_font_size(9)
        pdf.cell(0, 6, "YARA Eslestirmeleri:", new_x="LMARGIN", new_y="NEXT")
        for m in yara_results.get("matches", [])[:10]:
            rule = m.get("rule", "-")
            fname = Path(m.get("file", "")).name[:40]
            pdf.set_font_size(8)
            pdf.cell(0, 5, f"  - İmza: {rule} | Dosya: {fname}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
    if static_analysis:
        pdf.set_font_size(9)
        pdf.cell(0, 6, f"Statik Analiz: Entropi = {static_analysis.get('entropy', '-')} | {static_analysis.get('packed_guess', '-')}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font_size(8)
        pdf.cell(0, 5, f"Dosya: {static_analysis.get('file', '-')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
    if not yara_results and not static_analysis:
        pdf.cell(0, 6, "(YARA ve statik analiz sonuçları bulunamadı.)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ——— AG TRAFIGI (network_map.png) ———
    pdf.set_font_size(14)
    pdf.cell(0, 10, "4. Ağ Trafiği", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font_size(10)
    pdf.ln(2)

    if network_map_exists:
        try:
            pdf.image(str(network_map_path), x=10, w=190)
            pdf.ln(4)
        except Exception:
            pdf.cell(0, 6, "(Harita görseli eklenemedi)", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)
    else:
        pdf.cell(0, 6, "(Harita bulunamadı. tools/network_visualizer.py çalıştırın.)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ——— YASAL NOT (Buyuk puntolarla) ———
    pdf.add_page()
    pdf.set_font_size(14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "5. Yasal Not", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    if pdf._font_ok:
        pdf.set_font("UnicodeFont", "", 14)
    else:
        pdf.set_font("Helvetica", "", 14)
    pdf.set_font_size(14)
    pdf.multi_cell(0, 8, "Bu rapordaki tüm PII verileri @core/masker.py ile KVKK standartlarında maskelenmiştir.")
    pdf.ln(4)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Dijital Adli Bilisim PDF raporu olusturucu")
    parser.add_argument(
        "-o",
        "--output",
        default="reports/Forensic_Report_Final.pdf",
        help="Cikti PDF dosyasi",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path

    generate_pdf_report(project_root, output_path)
    print(f"PDF rapor kaydedildi: {output_path}")


if __name__ == "__main__":
    main()
