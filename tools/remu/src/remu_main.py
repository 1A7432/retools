"""Entry point used by the `remu` launcher (run with -I, so put our package on the path)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from remu.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
