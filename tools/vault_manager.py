#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vault_manager.py

Şüpheli dosyaları şifreli ZIP arşivine koyar.
Analiz sırasında dosyayı yalnızca bellek (RAM) üzerinde açar — diske yazmaz.
Böylece gerçek zamanlı antivirüs tarayıcılarından (File Watcher) kaçınılır.
"""

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Şüpheli sayılan uzantılar
SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".jar", ".bin"}


def _get_pyzipper():
    try:
        import pyzipper
        return pyzipper
    except ImportError:
        return None


def add_to_vault(
    evidence_dir: Path,
    vault_path: Path,
    password: bytes,
    patterns: list[str] | None = None,
    add_all: bool = False,
) -> list[str]:
    """evidence/ altındaki şüpheli dosyaları şifreli ZIP'e ekler."""
    pz = _get_pyzipper()
    if not pz:
        raise ImportError("pyzipper yüklü değil. pip install pyzipper")

    added = []
    vault_path = Path(vault_path)
    vault_path.parent.mkdir(parents=True, exist_ok=True)

    files_to_add = []
    for p in evidence_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() == ".zip" or p.resolve() == vault_path.resolve():
            continue
        if add_all:
            include = True
        elif patterns:
            include = any(p.match(pat) for pat in patterns)
        else:
            include = p.suffix.lower() in SUSPICIOUS_EXT
        if include:
            files_to_add.append(p)

    if not files_to_add:
        return []

    with pz.AESZipFile(str(vault_path), "w", pz.ZIP_DEFLATED, encryption=pz.WZ_AES) as zf:
        zf.setpassword(password)
        for fp in files_to_add:
            arcname = fp.relative_to(evidence_dir) if evidence_dir in fp.parents else fp.name
            zf.write(fp, arcname=str(arcname))
            added.append(str(arcname))

    return added


def read_in_memory(vault_path: Path, filename: str, password: bytes) -> bytes:
    """Arşivden dosyayı bellek üzerinde okur — diske yazmaz."""
    pz = _get_pyzipper()
    if not pz:
        raise ImportError("pyzipper yüklü değil. pip install pyzipper")

    with pz.AESZipFile(str(vault_path), "r") as zf:
        zf.setpassword(password)
        return zf.read(filename)


def list_vault(vault_path: Path, password: bytes) -> list[str]:
    """Arşivdeki dosya listesini döner."""
    pz = _get_pyzipper()
    if not pz:
        raise ImportError("pyzipper yüklü değil. pip install pyzipper")

    with pz.AESZipFile(str(vault_path), "r") as zf:
        zf.setpassword(password)
        return zf.namelist()


def analyze_yara_in_memory(data: bytes, rules_path: Path, project_root: Path) -> list[dict]:
    """YARA taramasını bellek üzerindeki veriyle yapar."""
    try:
        import yara
    except ImportError:
        return [{"error": "yara-python yüklü değil"}]

    if not rules_path.exists():
        return [{"error": f"Kural bulunamadı: {rules_path}"}]

    rules = yara.compile(filepath=str(rules_path))
    matches = rules.match(data=data)
    return [{"rule": m.rule, "strings": [{"id": s.identifier, "offset": s.instances[0].offset if s.instances else 0} for s in m.strings]} for m in matches]


def analyze_pe_in_memory(data: bytes) -> dict:
    """PE analizini bellek üzerindeki veriyle yapar."""
    try:
        import pefile
        pe = pefile.PE(data=data)
    except ImportError:
        return {"error": "pefile yüklü değil"}
    except Exception as e:
        return {"error": str(e)}

    result = {}
    try:
        result["headers"] = {
            "machine": hex(pe.FILE_HEADER.Machine) if pe.FILE_HEADER else None,
            "sections": pe.FILE_HEADER.NumberOfSections if pe.FILE_HEADER else None,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if pe.OPTIONAL_HEADER else None,
        }
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]:
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                for imp in list(entry.imports)[:3]:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord{imp.ordinal}"
                    imports.append({"dll": dll, "name": name})
        result["imports_sample"] = imports
    except Exception:
        result["error"] = "Parse hatası"
    pe.close()
    return result


def main():
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Şüpheli dosya vault yönetimi (şifreli ZIP, RAM'de analiz)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    add_p = sub.add_parser("add", help="evidence/ dosyalarını vault'a ekle")
    add_p.add_argument("--path", default="evidence", help="Kaynak dizin")
    add_p.add_argument("--vault", default="vault/suspicious_archive.zip", help="Vault ZIP yolu")
    add_p.add_argument("--all", action="store_true", help="Tüm dosyaları ekle (sadece şüpheli uzantılar değil)")
    add_p.add_argument("-p", "--password", help="Şifre (yoksa sorulur)")

    list_p = sub.add_parser("list", help="Vault içeriğini listele")
    list_p.add_argument("--vault", default="vault/suspicious_archive.zip")
    list_p.add_argument("-p", "--password", help="Şifre")

    read_p = sub.add_parser("read", help="Dosyayı RAM'de oku (diske yazmaz)")
    read_p.add_argument("filename", help="Vault içindeki dosya adı")
    read_p.add_argument("--vault", default="vault/suspicious_archive.zip")
    read_p.add_argument("-p", "--password", help="Şifre")

    analyze_p = sub.add_parser("analyze", help="Dosyayı RAM'de analiz et (YARA + PE)")
    analyze_p.add_argument("filename", help="Vault içindeki dosya adı")
    analyze_p.add_argument("--vault", default="vault/suspicious_archive.zip")
    analyze_p.add_argument("--rules", default="rules/malware_rules.yar")
    analyze_p.add_argument("-o", "--output", default="analysis/vault_analysis.json")
    analyze_p.add_argument("-p", "--password", help="Şifre")

    args = parser.parse_args()
    project_root = Path(__file__).resolve().parent.parent

    password = args.password.encode("utf-8") if getattr(args, "password", None) else None
    if not password:
        password = getpass.getpass("Vault şifresi: ").encode("utf-8")

    vault_path = project_root / getattr(args, "vault", "vault/suspicious_archive.zip")
    if not vault_path.is_absolute():
        vault_path = project_root / vault_path

    if args.cmd == "add":
        evidence_dir = project_root / args.path if not Path(args.path).is_absolute() else Path(args.path)
        added = add_to_vault(evidence_dir, vault_path, password, add_all=getattr(args, "all", False))
        print(f"Vault: {vault_path}")
        print(f"  {len(added)} dosya eklendi: {added}")

    elif args.cmd == "list":
        names = list_vault(vault_path, password)
        print(f"Vault: {vault_path}")
        for n in names:
            print(f"  - {n}")

    elif args.cmd == "read":
        data = read_in_memory(vault_path, args.filename, password)
        print(f"Okundu (RAM): {args.filename} — {len(data)} byte")

    elif args.cmd == "analyze":
        data = read_in_memory(vault_path, args.filename, password)
        rules_path = project_root / args.rules if not Path(args.rules).is_absolute() else Path(args.rules)

        yara_matches = analyze_yara_in_memory(data, rules_path, project_root)
        pe_result = analyze_pe_in_memory(data) if args.filename.lower().endswith((".exe", ".dll", ".scr")) else {"skip": "PE değil"}

        report = {
            "file": args.filename,
            "size": len(data),
            "yara": yara_matches,
            "pe": pe_result,
        }

        out_path = project_root / args.output if not Path(args.output).is_absolute() else Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"Analiz (RAM'de) tamamlandı: {out_path}")
        print(f"  YARA: {len(yara_matches)} eşleşme")
        pe_msg = pe_result.get("skip", "OK" if "error" not in pe_result else pe_result.get("error", "-"))
        print(f"  PE: {pe_msg}")


if __name__ == "__main__":
    main()
