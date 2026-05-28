import re

PATTERNS = [
    (r"\bunion\b\s+\bselect\b", "SQL Injection"),
    (r"(\bor\b|\band\b)\s+1\s*=\s*1", "SQL Injection"),
    (r"\bdrop\b\s+\btable\b", "SQL Injection"),
    (r"<script\b", "Cross-Site Scripting"),
    (r"javascript:", "Cross-Site Scripting"),
    (r"alert\(", "Cross-Site Scripting"),
    (r"document\.cookie", "Cross-Site Scripting"),
    (r"information_schema", "SQL Injection"),
    (r"--", "SQL Injection"),
    (r"/\*.*\*/", "SQL Injection"),
    (r"<img\b[^>]*onerror\b", "Cross-Site Scripting"),
]


def match_attack(payload: str) -> str | None:
    normalized = payload.lower()
    for regex, tag in PATTERNS:
        if re.search(regex, normalized, re.IGNORECASE | re.DOTALL):
            return tag
    return None
