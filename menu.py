#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RedzepTech Labs — Ana Menü / Yardım

Konteyner başladığında bu script çalışır.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           RedzepTech Labs — Dijital Adli Bilişim             ║
╠══════════════════════════════════════════════════════════════╣
║  Kullanılabilir araçlar:                                    ║
║                                                              ║
║  • Veri üretimi:                                             ║
║    python scripts/generate_test_data.py                      ║
║                                                              ║
║  • Log analizi:                                              ║
║    python scripts/log_analyzer.py                            ║
║                                                              ║
║  • Hash envanteri:                                           ║
║    python tools/hasher.py --path evidence/                   ║
║                                                              ║
║  • Timeline:                                                 ║
║    python tools/timeline_generator.py                        ║
║                                                              ║
║  • Tarayıcı geçmişi:                                         ║
║    python tools/browser_parser.py [History_dosyasi]         ║
║                                                              ║
║  • PDF rapor:                                                ║
║    python tools/reporter.py                                 ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Etkileşimli shell:  docker run -it <image> bash             ║
║  Tek komut:         docker run <image> python tools/hasher.py║
╚══════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
    sys.exit(0)
