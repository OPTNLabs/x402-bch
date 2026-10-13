"""Run the deterministic Python SDK lifecycle tests without pytest."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import test_sdk


def main() -> None:
    executed = 0
    for name in dir(test_sdk):
        if name.startswith("test_"):
            getattr(test_sdk, name)()
            executed += 1
    print(f"python SDK tests: {executed} passed")


if __name__ == "__main__":
    main()
