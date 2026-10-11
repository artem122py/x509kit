# -*- coding: utf-8 -*-
"""Точка входа `python -m x509kit`.

Эквивалент команды `x509kit` (entry point) и `python -m x509kit.cli`:

    python -m x509kit --version
    python -m x509kit info cert.pem
    python -m x509kit keygen --type ed25519 --out key.pem
    python -m x509kit csr create --key key.pem --subject "CN=x" --out x.csr
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
