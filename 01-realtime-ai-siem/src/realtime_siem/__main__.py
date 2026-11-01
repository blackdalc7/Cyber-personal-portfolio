"""Entry point for ``python -m realtime_siem``: start the UDP syslog listener."""

import sys

from .server import main

sys.exit(main())
