#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yara_scanner.py

YARA kuralları ile evidence/ klasörünü tarar.
Eşleşmeler core/masker.py ile maskelenerek analysis/yara_results.json'a kaydedilir.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker, mask_path


def _mask_value(val, masker: LabMasker, key: str):
    """Dosya yolu ve IP maskeleme."""
    if not isinstance(val, str):
        return val
    return masker.mask_text(mask_path(val))


def scan_evidence(evidence_dir: Path, rules_path: Path, masker: LabMasker) -> list[dict]:
    """evidence/ içindeki dosyaları YARA ile tarar."""
    try:
        import yara
    except ImportError:
        return [{"error": "yara-python yüklü değil. pip install yara-python"}]

    if not rules_path.exists():
        return [{"error": f"Kural dosyası bulunamadı: {rules_path}"}]

    try:
        rules = yara.compile(filepath=str(rules_path))
    except yara.SyntaxError as e:
        return [{"error": f"YARA kural hatası: {e}"}]

    results = []
    files = [p for p in evidence_dir.rglob("*") if p.is_file()]

    for file_path in files:
        try:
            matches = rules.match(str(file_path))
            if matches:
                for m in matches:
                    strings_found = []
                    for s in m.strings:
                        strings_found.append({
                            "identifier": s.identifier,
                            "offset": s.instances[0].offset if s.instances else 0,
                            "data": s.instances[0].matched_data.decode("utf-8", errors="replace")[:200] if s.instances and s.instances[0].matched_data else "",
                        })
                    results.append({
                        "file": str(file_path),
                        "rule": m.rule,
                        "tags": list(m.tags) if m.tags else [],
                        "strings": strings_found,
                    })
        except Exception as e:
            results.append({
                "file": str(file_path),
                "error": str(e),
            })

    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="YARA ile evidence/ taraması")
    parser.add_argument("--path", default="evidence", help="Taranacak dizin")
    parser.add_argument("--rules", default="rules/malware_rules.yar", help="YARA kural dosyası")
    parser.add_argument("-o", "--output", default="analysis/yara_results.json", help="Çıktı JSON")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    evidence_dir = project_root / args.path if not Path(args.path).is_absolute() else Path(args.path)
    rules_path = project_root / args.rules if not Path(args.rules).is_absolute() else Path(args.rules)
    output_path = project_root / args.output if not Path(args.output).is_absolute() else Path(args.output)

    if not evidence_dir.exists():
        print(f"Hata: {evidence_dir} bulunamadı.")
        sys.exit(1)

    masker = LabMasker()
    raw_results = scan_evidence(evidence_dir, rules_path, masker)

    masked_results = []
    for r in raw_results:
        if isinstance(r, dict) and "error" in r:
            masked_results.append(r)
            continue
        if isinstance(r, dict):
            masked = {}
            for k, v in r.items():
                if k == "file" and isinstance(v, str):
                    masked[k] = _mask_value(v, masker, k)
                elif k == "strings" and isinstance(v, list):
                    masked[k] = [
                        {sk: _mask_value(sv, masker, sk) if isinstance(sv, str) and sk == "data" else sv for sk, sv in s.items()}
                        for s in v
                    ]
                else:
                    masked[k] = _mask_value(v, masker, k) if isinstance(v, str) else v
            masked_results.append(masked)
        else:
            masked_results.append(r)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"matches": masked_results, "total": len(masked_results)}, f, indent=2, ensure_ascii=False)

    print(f"Tarama tamamlandı: {output_path}")
    print(f"  {len(masked_results)} eşleşme (KVKK maskeli)")


if __name__ == "__main__":
    main()
