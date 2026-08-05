"""Thin entry point so `python -m eval.clean_baseline.servers` works.

All implementation lives in the package __init__.
"""

from eval.clean_baseline.servers import main

if __name__ == "__main__":
    main()

