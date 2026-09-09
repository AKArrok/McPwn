"""Compatibility CLI for the frozen paired holdout evaluator.

The implementation lives in ``eval.holdout.runner`` so the holdout protocol has
one evaluator and one manifest schema.
"""

from __future__ import annotations

from eval.holdout.runner import main

if __name__ == "__main__":
    main()
