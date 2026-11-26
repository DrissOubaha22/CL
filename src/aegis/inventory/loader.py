"""Reading an inventory import file (spec §3.1).

Two shapes are accepted, because the people producing these files produce
both:

* **JSON** - either an :class:`~aegis.inventory.schemas.InventoryBatch`
  object, or a bare list of items.
* **CSV** - one row per discovered product, with the item fields as columns.

Scanner, ASM and cloud adapters are separate work; they parse their native
format and emit :class:`~aegis.inventory.schemas.InventoryItem` objects,
which is exactly what this loader produces.  Nothing downstream can tell the
difference.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from aegis.inventory.schemas import InventoryBatch, InventoryItem, InventorySource

__all__ = ["InventoryLoadError", "load_inventory_file"]

#: CSV columns that must be read as booleans rather than strings.
_BOOLEAN_FIELDS = ("from_distro_package",)
_TRUE_VALUES = frozenset({"1", "true", "t", "yes", "y"})


class InventoryLoadError(ValueError):
    """The file could not be read as an inventory import."""


def load_inventory_file(
    path: str | Path, *, source: InventorySource | None = None
) -> InventoryBatch:
    """Load and validate an inventory file.

    Args:
        path: A ``.json`` or ``.csv`` file.
        source: Override the source recorded on every item, for a file that
            does not state it.

    Raises:
        InventoryLoadError: on an unreadable file, an unknown extension, or
            a row that fails validation.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise InventoryLoadError(f"no such inventory file: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".json":
        batch = _load_json(file_path)
    elif suffix in (".csv", ".tsv"):
        batch = _load_csv(file_path, delimiter="\t" if suffix == ".tsv" else ",")
    else:
        raise InventoryLoadError(
            f"unsupported inventory format {suffix!r}; use .json, .csv or .tsv"
        )

    if source is not None:
        batch = batch.model_copy(
            update={
                "source": source,
                "items": [item.model_copy(update={"source": source}) for item in batch.items],
            }
        )
    return batch


def _load_json(path: Path) -> InventoryBatch:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryLoadError(f"{path}: {exc}") from exc

    try:
        if isinstance(payload, list):
            return InventoryBatch(items=[InventoryItem(**row) for row in payload])
        if isinstance(payload, dict):
            return InventoryBatch(**payload)
    except ValidationError as exc:
        raise InventoryLoadError(f"{path}: {_describe(exc)}") from exc

    raise InventoryLoadError(f"{path}: expected a JSON object or array")


def _load_csv(path: Path, *, delimiter: str) -> InventoryBatch:
    items: list[InventoryItem] = []
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            if reader.fieldnames is None:
                raise InventoryLoadError(f"{path}: no header row")
            for line_number, row in enumerate(reader, start=2):
                try:
                    items.append(InventoryItem(**_clean_row(row)))
                except ValidationError as exc:
                    raise InventoryLoadError(f"{path}:{line_number}: {_describe(exc)}") from exc
    except OSError as exc:
        raise InventoryLoadError(f"{path}: {exc}") from exc

    return InventoryBatch(items=items)


def _clean_row(row: dict[str, str | None]) -> dict[str, Any]:
    """Turn CSV strings into the types the model expects."""
    cleaned: dict[str, Any] = {}
    for key, value in row.items():
        if key is None:
            continue
        name = key.strip()
        text = (value or "").strip()
        if text == "":
            continue
        if name in _BOOLEAN_FIELDS:
            cleaned[name] = text.lower() in _TRUE_VALUES
        elif name == "cpes":
            cleaned[name] = [part.strip() for part in text.split(";") if part.strip()]
        elif name == "port":
            cleaned[name] = int(text)
        else:
            cleaned[name] = text
    return cleaned


def _describe(exc: ValidationError) -> str:
    """A one-line summary of what failed validation."""
    problems = [
        f"{'.'.join(str(p) for p in error['loc']) or 'row'}: {error['msg']}"
        for error in exc.errors()[:3]
    ]
    return "; ".join(problems)
