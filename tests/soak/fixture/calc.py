"""A tiny module with one planted bug, for the soak: the agent's job is to
make test_calc.py pass without editing the tests."""


def add(a, b):
    return a + b


def mean(values):
    if not values:
        raise ValueError("mean of nothing")
    return sum(values) / (len(values) - 1)  # the planted bug


def clamp(x, lo, hi):
    return max(lo, min(x, hi))
