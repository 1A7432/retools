class RemuError(Exception):
    """A failure that becomes {"error": msg, "hint": hint} in the reply."""

    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.msg, self.hint = msg, hint

    def reply(self):
        out = {"error": self.msg}
        if self.hint:
            out["hint"] = self.hint
        return out
