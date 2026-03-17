"""
utils/masker.py

IP, kullanıcı adı ve e-posta maskeleme fonksiyonları.
"""

import re


def mask_ip(ip: str) -> str:
    """
    IP adresinin son iki oktetini gizler.
    Örnek: 192.168.1.50 -> 192.168.x.x
    """
    if not ip or not isinstance(ip, str):
        return ip
    pattern = r"^(\d{1,3}\.\d{1,3})\.(\d{1,3}\.\d{1,3})$"
    match = re.match(pattern, str(ip).strip())
    if match:
        return f"{match.group(1)}.x.x"
    return ip


def mask_username(name: str) -> str:
    """
    Kullanıcı adının ilk ve son harfi hariç yıldız koyar.
    Örnek: admin -> a***n
    """
    if not name or not isinstance(name, str):
        return name
    name = str(name).strip()
    if not name:
        return ""
    if len(name) <= 2:
        return "*" * len(name)
    return f"{name[0]}{'*' * (len(name) - 2)}{name[-1]}"


def mask_email(email: str) -> str:
    """
    Domain kısmını koruyup kullanıcı adını (local part) maskeler.
    Örnek: admin@example.com -> a***n@example.com
    """
    if not email or not isinstance(email, str):
        return email
    match = re.match(r"^([^@]+)@(.+)$", str(email).strip())
    if match:
        local, domain = match.group(1), match.group(2)
        masked_local = mask_username(local)
        return f"{masked_local}@{domain}"
    return email


def mask_path(path: str) -> str:
    """
    Dosya yolundaki kullanıcı adını gizler (C:\\Users\\Ali\\... -> C:\\Users\\***\\...).
    """
    if not path or not isinstance(path, str):
        return path
    orig = str(path)
    normalized = orig.replace("\\", "/")
    normalized = re.sub(r"(/Users?)/([^/]+)(/|$)", r"\1/***\3", normalized, flags=re.I)
    normalized = re.sub(r"(/home)/([^/]+)(/|$)", r"\1/***\3", normalized)
    return normalized.replace("/", "\\") if "\\" in orig else normalized


def clean_log(text: str) -> str:
    """
    Metin içindeki tüm IP ve e-postaları regex ile bulup maskeler.
    """
    result = text
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    result = re.sub(ip_pattern, lambda m: mask_ip(m.group(0)), result)
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    result = re.sub(email_pattern, lambda m: mask_email(m.group(0)), result)
    return result
