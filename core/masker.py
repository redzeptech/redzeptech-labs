"""
core/masker.py — Maskeleme ve temel mantık

LabMasker sınıfı: IPv4 ve e-posta maskeleme.
Tüm test senaryoları bu sınıfı miras almalıdır.
"""

import re


class LabMasker:
    """
    Metin içindeki IPv4 ve e-postaları maskeler.
    - IPv4: 192.168.x.x formatı (ilk iki oktet görünür)
    - E-posta: u***r@domain.com formatı (local part ilk/son harf, domain korunur)
    """

    # Regex desenleri
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    IPV4_MATCH_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3})\.(\d{1,3}\.\d{1,3})$")
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    EMAIL_MATCH_PATTERN = re.compile(r"^([^@]+)@(.+)$")

    def mask_ip(self, ip: str) -> str:
        """
        IPv4 adresini 192.168.x.x formatına çevirir.
        Örnek: 10.0.0.50 -> 10.0.x.x
        """
        if not ip or not isinstance(ip, str):
            return ip
        match = self.IPV4_MATCH_PATTERN.match(str(ip).strip())
        if match:
            return f"{match.group(1)}.x.x"
        return ip

    def mask_email(self, email: str) -> str:
        """
        E-postayı u***r@domain.com formatına çevirir.
        Local part: ilk ve son harf görünür, ortası yıldız.
        """
        if not email or not isinstance(email, str):
            return email
        match = self.EMAIL_MATCH_PATTERN.match(str(email).strip())
        if match:
            local, domain = match.group(1), match.group(2)
            masked_local = self._mask_local_part(local)
            return f"{masked_local}@{domain}"
        return email

    def mask_mac(self, mac: str) -> str:
        """MAC adresinin son 3 oktetini maskeler (aa:bb:cc:xx:xx:xx)."""
        if not mac or not isinstance(mac, str):
            return mac
        s = str(mac).strip()
        parts = re.split(r"[:-]", s)
        if len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
            return ":".join(parts[:3] + ["xx", "xx", "xx"])
        return mac

    def _mask_local_part(self, local: str) -> str:
        """E-posta local part: ilk ve son harf görünür, ortası *** (u***r formatı)."""
        if not local:
            return ""
        if len(local) <= 2:
            return "*" * len(local)
        # u***r formatı: ilk + *** + son (örnek için 3 yıldız)
        return f"{local[0]}***{local[-1]}"

    def mask_text(self, text: str) -> str:
        """
        Metin içindeki tüm IPv4 ve e-postaları bulup maskeler.
        """
        if not text:
            return text
        result = str(text)
        result = self.IPV4_PATTERN.sub(lambda m: self.mask_ip(m.group(0)), result)
        result = self.EMAIL_PATTERN.sub(lambda m: self.mask_email(m.group(0)), result)
        return result


# Varsayılan instance (geriye dönük uyumluluk)
_default_masker = LabMasker()


def mask_ip(ip: str) -> str:
    """LabMasker.mask_ip delegasyonu."""
    return _default_masker.mask_ip(ip)


def mask_username(name: str) -> str:
    """LabMasker._mask_local_part delegasyonu (kullanıcı adı için)."""
    return _default_masker._mask_local_part(str(name) if name else "")


def mask_email(email: str) -> str:
    """LabMasker.mask_email delegasyonu."""
    return _default_masker.mask_email(email)


def mask_path(path: str) -> str:
    """Dosya yolundaki kullanıcı adını gizler."""
    if not path or not isinstance(path, str):
        return path
    orig = str(path)
    normalized = orig.replace("\\", "/")
    normalized = re.sub(r"(/Users?)/([^/]+)(/|$)", r"\1/***\3", normalized, flags=re.I)
    normalized = re.sub(r"(/home)/([^/]+)(/|$)", r"\1/***\3", normalized)
    return normalized.replace("/", "\\") if "\\" in orig else normalized


def clean_log(text: str) -> str:
    """LabMasker.mask_text delegasyonu."""
    return _default_masker.mask_text(text)
