"""Allow ``python -m watchfloor``."""

import sys

from .cli import main

sys.exit(main())
