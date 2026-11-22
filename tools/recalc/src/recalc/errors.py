"""Error types. Every failure the user can cause becomes a CalcError, which the
command line turns into an {"error", "hint", "line"} reply."""

from __future__ import annotations


MAX_MSG, MAX_HINT = 400, 400


def _clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 30] + "...[cut %d chars]" % (len(s) - n + 30)


def short(v, n=40):
    """A bounded description of a value for error messages (never a full repr)."""
    t = type(v)
    if t in (str, bytes):
        r = repr(v[:n])
        return r + ("...(%d long)" % len(v) if len(v) > n else "")
    if t is int:
        return hex(v) if v.bit_length() <= 4 * n else "an integer of %d bits" % v.bit_length()
    if t in (bool, type(None)):
        return repr(v)
    if t in (list, tuple, dict):
        return "a %s of %d items" % (t.__name__, len(v))
    return "a %s" % t.__name__


class CalcError(Exception):
    def __init__(self, msg, hint="", line=None):
        msg, hint = _clip(msg, MAX_MSG), _clip(hint, MAX_HINT) if hint else ""
        super().__init__(msg)
        self.msg, self.hint, self.line = msg, hint, line

    def reply(self):
        out = {"error": self.msg, "hint": self.hint or ""}
        if self.line is not None:
            out["line"] = self.line
        return out


class LimitError(CalcError):
    """A resource limit was hit; `limit` names it."""

    def __init__(self, limit, msg, hint=""):
        super().__init__("limit '%s' exceeded: %s" % (limit, msg), hint)
        self.limit = limit


class TimeLimit(BaseException):
    """Raised from the SIGALRM handler. A BaseException so that nothing on the
    way up mistakes it for an ordinary failure of the operation it interrupted."""
