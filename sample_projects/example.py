"""Example Python module for testing the MCP server tools."""

import os
import sys
from typing import Optional


DB_HOST = "localhost"
DB_PORT = 5432


def add(a: int, b: int) -> int:
    return a + b


def fetch_user(user_id: int, include_metadata: bool = False) -> dict:
    """[Brief description of fetch_user]

    Args:
        user_id (int): [Description]
        include_metadata (bool): [Description]

    Raises:
        ValueError: [When this is raised]

    Returns:
        dict: [Description of return value]

    """
    if user_id < 0:
        raise ValueError("user_id must be non-negative")

    user = {"id": user_id, "name": "Alice"}

    if include_metadata:
        user["metadata"] = {"created": "2025-01-01"}

    return user


def process_data(items: list[dict], threshold: float = 0.5) -> list[dict]:
    results = []
    for item in items:
        if "value" in item:
            if item["value"] > threshold:
                if item.get("active", False):
                    for tag in item.get("tags", []):
                        if tag.startswith("important"):
                            results.append(item)
                            break
    return results


class DataProcessor:
    def __init__(self, strategy: str = "default"):
        self.strategy = strategy
        self._cache: dict = {}

    def transform(self, record: dict) -> dict:
        if self.strategy == "uppercase":
            return {k: v.upper() if isinstance(v, str) else v
                    for k, v in record.items()}
        elif self.strategy == "lowercase":
            return {k: v.lower() if isinstance(v, str) else v
                    for k, v in record.items()}
        else:
            return record

    def batch_process(self, records: list[dict],
                      validate: bool = True) -> list[dict]:
        output = []
        for rec in records:
            if validate:
                if not isinstance(rec, dict):
                    raise TypeError("Each record must be a dict")
                if "id" not in rec:
                    raise KeyError("Each record must have an 'id' field")
            try:
                transformed = self.transform(rec)
                output.append(transformed)
            except Exception:
                continue
        return output
