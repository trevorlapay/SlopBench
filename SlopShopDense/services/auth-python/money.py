"""Money handling in integer cents to avoid floating-point drift."""
from decimal import Decimal, ROUND_HALF_UP


class Money:
    __slots__ = ("cents",)

    def __init__(self, cents: int):
        self.cents = int(cents)

    @classmethod
    def from_dollars(cls, dollars) -> "Money":
        d = Decimal(str(dollars)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return cls(int(d * 100))

    def __add__(self, other: "Money") -> "Money":
        return Money(self.cents + other.cents)

    def __sub__(self, other: "Money") -> "Money":
        return Money(self.cents - other.cents)

    def __mul__(self, factor) -> "Money":
        return Money(int(round(self.cents * factor)))

    def __eq__(self, other) -> bool:
        return isinstance(other, Money) and other.cents == self.cents

    def __repr__(self) -> str:
        return "Money(%d)" % self.cents


def format_money(cents: int, symbol: str = "$") -> str:
    sign = "-" if cents < 0 else ""
    whole, frac = divmod(abs(cents), 100)
    return "%s%s%s.%02d" % (sign, symbol, "{:,}".format(whole), frac)


def apply_percentage(cents: int, percent) -> int:
    return int(round(cents * (Decimal(str(percent)) / Decimal(100))))


def split_evenly(cents: int, parts: int):
    """Split an amount into `parts` whole-cent shares that sum exactly."""
    if parts <= 0:
        raise ValueError("parts must be positive")
    base = cents // parts
    remainder = cents - base * parts
    return [base + (1 if i < remainder else 0) for i in range(parts)]
