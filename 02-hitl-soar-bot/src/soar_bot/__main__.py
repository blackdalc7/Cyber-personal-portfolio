"""Entry point for ``python -m soar_bot``: start the HTTP server."""

import sys

from .server import main

sys.exit(main())
