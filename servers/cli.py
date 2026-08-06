"""Console entry point: ``safe-mcp <server-name>`` starts one server.

Wiring only. Each server keeps its own ``main()`` — this just picks one by name,
so ``python -m servers.terminal.server`` and ``python -m servers.files.server``
still work unchanged for debugging.
"""

from __future__ import annotations

import sys

from servers.files.server import main as files_main
from servers.terminal.server import main as terminal_main

SERVERS = {"terminal": terminal_main, "files": files_main}


def main() -> None:
    try:
        target = SERVERS[sys.argv[1]]
    except (IndexError, KeyError):
        print(f"usage: safe-mcp {{{'|'.join(SERVERS)}}} [--config PATH]", file=sys.stderr)
        raise SystemExit(1)
    target(sys.argv[2:])


if __name__ == "__main__":  # pragma: no cover
    main()
