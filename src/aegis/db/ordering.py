"""Ordering by enum severity rather than alphabetically.

Enum-valued columns are stored as ``VARCHAR`` (see
:mod:`aegis.db.types`), so ``ORDER BY confidence DESC`` orders
``medium, low, high`` - alphabetical, and wrong for every one of these
vocabularies.  These helpers build the ``CASE`` expression that orders by
meaning instead.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from sqlalchemy import Case, case
from sqlalchemy.orm import InstrumentedAttribute

from aegis.core.enums import ExploitStatus, MatchConfidence

__all__ = ["confidence_order", "exploit_status_order", "rank_order"]


def rank_order(column: InstrumentedAttribute[Any], ranks: dict[StrEnum, int]) -> Case[int]:
    """A ``CASE`` mapping each enum value to its rank, for ``ORDER BY``.

    Unknown values sort last ascending (``-1``), which keeps a value written
    by an older release from jumping to the top of a list.
    """
    return case(
        {member.value: rank for member, rank in ranks.items()},
        value=column,
        else_=-1,
    )


def confidence_order(column: InstrumentedAttribute[Any]) -> Case[int]:
    """Order ``low < medium < high`` (spec §5.3)."""
    return rank_order(column, {member: member.rank for member in MatchConfidence})


def exploit_status_order(column: InstrumentedAttribute[Any]) -> Case[int]:
    """Order ``none < poc < active`` (spec §7.1)."""
    return rank_order(column, {member: member.rank for member in ExploitStatus})
