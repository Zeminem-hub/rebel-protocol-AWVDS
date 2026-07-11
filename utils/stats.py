class RequestCounter:
    """Thread-agnostic per-scan HTTP request counter. Passed to scanners
    so we can surface total load in the diagnostics."""

    __slots__ = ("count",)

    def __init__(self):
        self.count = 0

    def bump(self, n: int = 1) -> None:
        self.count += n
