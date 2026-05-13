"""PostgreSQL Query Plan Analyzer — GUI entry point (wrapper around `pg_query_analyzer.app`)."""

import sys

from pg_query_analyzer.app import run_gui

if __name__ == "__main__":
    sys.exit(run_gui())
