"""Allow `python -m pg_query_analyzer`."""

import sys

from pg_query_analyzer.app import run_gui


def main() -> None:
    sys.exit(run_gui())


if __name__ == "__main__":
    main()
