#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
static_analyzer.py

PE (Windows Executable) dosyalarının statik analizini yapar.
- Header bilgileri ve import tabloları (pefile)
- Okunabilir string çıkarımı
- Entropi hesaplama (packed/şifreli tespiti)
- core/masker.py ile PII maskeleme
"""

import json
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker, mask_path


def calculate_entropy(data: bytes) -> float:
    """Dosya verisinin Shannon entropisini hesaplar."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Okunabilir ASCII string'leri çıkarır."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    matches = re.findall(pattern, data)
    return [m.decode("ascii", errors="replace") for m in matches]


def analyze_pe(pe_path: Path) -> dict | None:
    """PE dosyasını analiz eder. Hata durumunda None döner."""
    try:
        import pefile

        pe = pefile.PE(str(pe_path))
    except Exception as e:
        return {"error": str(e)}

    result = {}

    # Header bilgileri
    try:
        result["headers"] = {
            "e_magic": hex(pe.DOS_HEADER.e_magic) if hasattr(pe, "DOS_HEADER") else None,
            "machine": hex(pe.FILE_HEADER.Machine) if pe.FILE_HEADER else None,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections if pe.FILE_HEADER else None,
            "timestamp": pe.FILE_HEADER.TimeDateStamp if pe.FILE_HEADER else None,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if pe.OPTIONAL_HEADER else None,
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase) if pe.OPTIONAL_HEADER else None,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem if pe.OPTIONAL_HEADER else None,
        }
    except Exception:
        result["headers"] = {"error": "Header okunamadı"}

    # Import tablosu
    imports = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord{imp.ordinal}"
                    imports.append({"dll": dll, "name": name})
        result["imports"] = imports[:200]  # İlk 200
    except Exception:
        result["imports"] = []

    # Sections
    sections = []
    try:
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            sections.append({
                "name": name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": round(sec.get_entropy(), 4) if hasattr(sec, "get_entropy") else None,
            })
        result["sections"] = sections
    except Exception:
        result["sections"] = []

    pe.close()
    return result


def _mask_string(s: str, masker: LabMasker) -> str:
    """Dosya yolu ve IP maskeleme."""
    if not isinstance(s, str):
        return s
    return masker.mask_text(mask_path(s))


def mask_report(report: dict, masker: LabMasker) -> dict:
    """Rapordaki tüm string'lerde dosya yolları ve IP'leri maskeler."""

    def _walk(obj):
        if isinstance(obj, dict):
            return {k: _walk(_mask_string(v, masker) if isinstance(v, str) else v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(_mask_string(i, masker) if isinstance(i, str) else i) for i in obj]
        return obj

    return _walk(report)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="PE dosya statik analizi")
    parser.add_argument("pe_file", help="PE dosya yolu")
    parser.add_argument("-o", "--output", default="analysis/malware_static_report.json", help="Çıktı JSON")
    parser.add_argument("--min-string-len", type=int, default=4, help="Minimum string uzunluğu")
    parser.add_argument("--max-strings", type=int, default=500, help="Maksimum string sayısı")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    pe_path = Path(args.pe_file)
    if not pe_path.is_absolute():
        pe_path = project_root / pe_path

    if not pe_path.exists():
        print(f"Hata: {pe_path} bulunamadı.")
        sys.exit(1)

    masker = LabMasker()

    # Ham veri
    with open(pe_path, "rb") as f:
        raw_data = f.read()

    # Entropi
    entropy = calculate_entropy(raw_data)
    packed_guess = "Yüksek olasılıkla paketlenmiş/şifreli" if entropy > 7.0 else "Normal" if entropy < 6.0 else "Belirsiz"

    # String'ler
    strings = extract_strings(raw_data, args.min_string_len)
    strings = strings[: args.max_strings]

    # PE analizi
    pe_info = analyze_pe(pe_path)

    report = {
        "file": mask_path(str(pe_path)),
        "entropy": entropy,
        "packed_guess": packed_guess,
        "file_size": len(raw_data),
        "strings_count": len(strings),
        "strings_sample": strings[:100],
        "pe_analysis": pe_info,
    }

    report = mask_report(report, masker)

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_root / output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Rapor kaydedildi: {output_path}")
    print(f"  Entropi: {entropy} ({packed_guess})")
    print(f"  String sayısı: {len(strings)}")


if __name__ == "__main__":
    main()
