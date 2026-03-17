"""
Test senaryoları — LabMasker sınıfını miras alır.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.masker import LabMasker


class TestMaskerScenario(LabMasker):
    """Test senaryosu: LabMasker'dan miras alır."""

    def run(self) -> None:
        """Temel maskeleme testleri."""
        assert self.mask_ip("192.168.1.50") == "192.168.x.x"
        assert self.mask_email("user@domain.com") == "u***r@domain.com"
        assert self.mask_text("Login from 10.0.0.1 by admin@test.com") == "Login from 10.0.x.x by a***n@test.com"
        print("Tüm testler geçti.")


if __name__ == "__main__":
    scenario = TestMaskerScenario()
    scenario.run()
