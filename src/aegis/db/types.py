"""Custom column types.

Enum-valued columns are stored as plain ``VARCHAR`` - readable in psql, easy
to constrain with a CHECK, and free of PostgreSQL ENUM migration pain - but
they must come *back* as the enum member.  Without that round trip a consumer
comparing ``record.exploit_status is ExploitStatus.ACTIVE`` silently gets
``False``, which the scoring engine of spec §7 would do.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import Dialect, String, TypeDecorator

__all__ = ["StrEnumType"]


class StrEnumType(TypeDecorator[Any]):
    """Persist a :class:`enum.StrEnum` as its value, load it as the member."""

    impl = String
    cache_ok = True

    def __init__(self, enum_class: type[StrEnum], length: int = 32) -> None:
        self._enum_class = enum_class
        super().__init__(length=length)

    @property
    def python_type(self) -> type[StrEnum]:
        return self._enum_class

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        if isinstance(value, self._enum_class):
            return value.value
        # Accept the raw string too, so bulk inserts and literals still work.
        return self._enum_class(value).value

    def process_result_value(self, value: Any, dialect: Dialect) -> StrEnum | None:
        if value is None:
            return None
        return self._enum_class(value)
