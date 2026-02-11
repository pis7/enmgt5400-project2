"""Example Python module for testing the MCP server tools."""

import os
import sys
from typing import Optional


DB_HOST = "localhost"
DB_PORT = 5432


def add(a: int, b: int) -> int:
    """[Brief description of add]

    Args:
        a (int): [Description]
        b (int): [Description]

    Returns:
        int: [Description of return value]

    """
    return a + b


def fetch_user(user_id: int, include_metadata: bool = False) -> dict:
    """Fetch a user record from the database."""
    if user_id < 0:
        raise ValueError("user_id must be non-negative")

    user = {"id": user_id, "name": "Alice"}

    if include_metadata:
        user["metadata"] = {"created": "2025-01-01"}

    return user


def process_data(items: list[dict], threshold: float = 0.5) -> list[dict]:
    """[Brief description of process_data]

    Args:
        items (list[dict]): [Description]
        threshold (float): [Description]

    Returns:
        list[dict]: [Description of return value]

    """
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
    """Processes data records with configurable strategies."""

    def __init__(self, strategy: str = "default"):
        """[Brief description of __init__]

        Args:
            strategy (str): [Description]

        """
        self.strategy = strategy
        self._cache: dict = {}

    def transform(self, record: dict) -> dict:
        """[Brief description of transform]

        Args:
            record (dict): [Description]

        Returns:
            dict: [Description of return value]

        """
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
        """[Brief description of batch_process]

        Args:
            records (list[dict]): [Description]
            validate (bool): [Description]

        Raises:
            KeyError: [When this is raised]
            TypeError: [When this is raised]

        Returns:
            list[dict]: [Description of return value]

        """
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
