"""Data pipeline module demonstrating deep nesting and class hierarchies."""

from typing import Any, Optional


BATCH_SIZE = 100
MAX_RETRIES = 3


class PipelineError(Exception):
    """Raised when a pipeline stage encounters an unrecoverable error."""

    pass


class BaseTransformer:
    """Base class for all pipeline transformers."""

    def __init__(self, name: str):
        self.name = name
        self._enabled = True

    def transform(self, record: dict) -> dict:
        raise NotImplementedError

    def is_enabled(self) -> bool:
        return self._enabled


class FilterTransformer(BaseTransformer):

    def __init__(self, name: str, required_fields: list[str]):
        super().__init__(name)
        self.required_fields = required_fields

    def transform(self, record: dict) -> dict:
        for field in self.required_fields:
            if field not in record:
                raise PipelineError(f"Missing required field: {field}")
        return record


class MapTransformer(BaseTransformer):

    def __init__(self, name: str, field_map: dict[str, str]):
        super().__init__(name)
        self.field_map = field_map

    def transform(self, record: dict) -> dict:
        result = {}
        for old_key, new_key in self.field_map.items():
            if old_key in record:
                result[new_key] = record[old_key]
        return result


def run_pipeline(
    records: list[dict],
    transformers: list[BaseTransformer],
    strict: bool = True,
    max_errors: int = 10,
) -> dict[str, Any]:
    output = []
    errors = []
    skipped = 0
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            if strict:
                raise PipelineError(f"Record {i} is not a dict")
            else:
                skipped += 1
                continue
        current = record
        failed = False
        for transformer in transformers:
            if transformer.is_enabled():
                try:
                    current = transformer.transform(current)
                except PipelineError as e:
                    errors.append({"record": i, "error": str(e)})
                    failed = True
                    if len(errors) > max_errors:
                        if strict:
                            raise PipelineError(
                                f"Too many errors ({len(errors)})"
                            )
                    break
        if not failed:
            output.append(current)

    return {
        "processed": output,
        "errors": errors,
        "skipped": skipped,
        "total": len(records),
    }


def build_nested_report(
    data: list[dict], group_key: str, sub_group_key: Optional[str] = None
) -> dict:
    report: dict = {}
    for item in data:
        if group_key in item:
            group = item[group_key]
            if group not in report:
                report[group] = {"count": 0, "items": [], "sub_groups": {}}
            report[group]["count"] += 1
            report[group]["items"].append(item)
            if sub_group_key and sub_group_key in item:
                sub = item[sub_group_key]
                if sub not in report[group]["sub_groups"]:
                    report[group]["sub_groups"][sub] = []
                report[group]["sub_groups"][sub].append(item)
    return report


if __name__ == "__main__":
    sample = [
        {"name": "Alice", "dept": "Engineering", "team": "Backend"},
        {"name": "Bob", "dept": "Engineering", "team": "Frontend"},
        {"name": "Carol", "dept": "Design", "team": "UX"},
    ]
    result = build_nested_report(sample, "dept", "team")
    print(result)
