"""Refusal type for the reference verifier/checker.  Fail-closed: any
Refusal means NO report (production) / expected-negative (tests)."""


class Refusal(Exception):
    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__("%s%s" % (code, (": " + detail) if detail else ""))


def need(condition, code, detail=""):
    if not condition:
        raise Refusal(code, detail)
