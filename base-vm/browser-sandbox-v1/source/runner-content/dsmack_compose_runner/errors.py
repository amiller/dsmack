"""Runner error types.

Every operational failure the runner detects carries a stable machine code
so callers (and tests) can assert the exact fail-closed class. Diagnostics
are value-free: they never echo caller input values (the contract's D06/S06
rule applies to the runner too -- a diagnostic may name a FIELD, never a
VALUE).
"""

from __future__ import annotations


class RunnerError(Exception):
    """A fail-closed runner condition."""

    def __init__(self, code: str, message: str):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message
