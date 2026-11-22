"""Entry point used by the `recalc` launcher (run with -I -S, so put our package on the path)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from recalc.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
