import re
from detector import match_attack


def detect_attack(payload: str) -> str | None:
    return match_attack(payload)
