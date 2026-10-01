"""Command line entry point: ``python3 -m auto_review <stage>``."""

import argparse
import sys

from . import approve, decide, report, review, screen
from .config import Config

STAGES = {
    "screen": screen.run,
    "review": review.run,
    "decide": decide.run,
    "report": report.run,
    "approve": approve.run,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="auto_review")
    parser.add_argument("stage", choices=sorted(STAGES))
    arguments = parser.parse_args(argv)
    STAGES[arguments.stage](Config.from_env())
    return 0


if __name__ == "__main__":
    sys.exit(main())
