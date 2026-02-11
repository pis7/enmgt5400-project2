"""Input validation utilities with high branching complexity."""

import re
from typing import Any


VALID_ROLES = {"admin", "editor", "viewer", "guest"}
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_user_input(data: dict[str, Any]) -> list[str]:
    errors = []
    if "username" not in data:
        errors.append("username is required")
    elif not isinstance(data["username"], str):
        errors.append("username must be a string")
    elif len(data["username"]) < 3:
        errors.append("username must be at least 3 characters")
    elif len(data["username"]) > 50:
        errors.append("username must be at most 50 characters")
    elif not data["username"].isalnum():
        errors.append("username must be alphanumeric")

    if "email" not in data:
        errors.append("email is required")
    elif not isinstance(data["email"], str):
        errors.append("email must be a string")
    elif not EMAIL_PATTERN.match(data["email"]):
        errors.append("email format is invalid")

    if "age" in data:
        if not isinstance(data["age"], int):
            errors.append("age must be an integer")
        elif data["age"] < 0 or data["age"] > 150:
            errors.append("age must be between 0 and 150")

    if "role" in data:
        if data["role"] not in VALID_ROLES:
            errors.append(f"role must be one of {VALID_ROLES}")

    return errors


def validate_password(password: str) -> tuple[bool, list[str]]:
    issues = []
    if len(password) < 8:
        issues.append("must be at least 8 characters")
    if len(password) > 128:
        issues.append("must be at most 128 characters")
    if not any(c.isupper() for c in password):
        issues.append("must contain an uppercase letter")
    if not any(c.islower() for c in password):
        issues.append("must contain a lowercase letter")
    if not any(c.isdigit() for c in password):
        issues.append("must contain a digit")
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
        issues.append("must contain a special character")
    return len(issues) == 0, issues


def sanitize_html(text: str) -> str:
    """Remove potentially dangerous HTML tags from text.

    Args:
        text (str): Raw text that may contain HTML.

    Returns:
        str: Sanitized text with dangerous tags removed.

    """
    dangerous_tags = ["script", "iframe", "object", "embed", "form"]
    result = text
    for tag in dangerous_tags:
        result = re.sub(
            rf"</?{tag}[^>]*>", "", result, flags=re.IGNORECASE
        )
    return result
