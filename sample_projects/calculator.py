"""Simple calculator module for demonstrating low-complexity metrics."""


def add(a: float, b: float) -> float:
    return a + b


def subtract(a: float, b: float) -> float:
    return a - b


def multiply(a: float, b: float) -> float:
    return a * b


def divide(a: float, b: float) -> float:
    if b == 0:
        raise ZeroDivisionError("Cannot divide by zero")
    return a / b


def power(base: float, exponent: int) -> float:
    result = 1
    for _ in range(abs(exponent)):
        result *= base
    if exponent < 0:
        return 1 / result
    return result


class ScientificCalculator:
    """A calculator with memory and history tracking."""

    def __init__(self):
        self.memory: float = 0.0
        self.history: list[str] = []

    def store(self, value: float) -> None:
        self.memory = value
        self.history.append(f"stored {value}")

    def recall(self) -> float:
        return self.memory

    def clear(self) -> None:
        self.memory = 0.0
        self.history.clear()
