"""Repository helpers for querying observed plan snapshots."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from pg_query_analyzer.observed_plans.models import ObservedPlanSnapshot
from pg_query_analyzer.observed_plans.sources.pg_stat_statements import (
    workload_candidates_from_pg_stat_rows,
)
from pg_query_analyzer.observed_plans.sources.journal import load_observed_snapshots_from_journal
from pg_query_analyzer.observed_plans.storage.sqlite import load_snapshots as load_sqlite_snapshots


class ObservedPlanRepository:
    """Read-only repository facade over normalized plan snapshots.

    The first implementation is intentionally backed by the existing JSON
    journal. Later it can be replaced by SQLite or an external source without
    changing UI code that consumes snapshots.
    """

    def __init__(self, snapshots: Iterable[ObservedPlanSnapshot]):
        self._snapshots = sorted(
            list(snapshots),
            key=lambda snapshot: snapshot.captured_at,
        )

    @classmethod
    def from_journal(
        cls, journal_file: str = "query_plans_journal.json"
    ) -> "ObservedPlanRepository":
        return cls(load_observed_snapshots_from_journal(journal_file))

    @classmethod
    def from_sqlite(cls, db_path: str) -> "ObservedPlanRepository":
        return cls(load_sqlite_snapshots(db_path))

    def list_snapshots(self) -> List[ObservedPlanSnapshot]:
        return list(self._snapshots)

    def group_by_query_identity(self) -> Dict[str, List[ObservedPlanSnapshot]]:
        groups: Dict[str, List[ObservedPlanSnapshot]] = defaultdict(list)
        for snapshot in self._snapshots:
            groups[_query_identity(snapshot)].append(snapshot)
        return dict(groups)

    def changed_plan_groups(self) -> Dict[str, List[ObservedPlanSnapshot]]:
        changed: Dict[str, List[ObservedPlanSnapshot]] = {}
        for identity, snapshots in self.group_by_query_identity().items():
            hashes = {
                snapshot.plan_shape_hash for snapshot in snapshots if snapshot.plan_shape_hash
            }
            if len(hashes) > 1:
                changed[identity] = snapshots
        return changed

    def workload_candidates_from_pg_stat_rows(self, rows):
        return workload_candidates_from_pg_stat_rows(rows, self._snapshots)


def _query_identity(snapshot: ObservedPlanSnapshot) -> str:
    if snapshot.queryid:
        return f"queryid:{snapshot.queryid}"
    if snapshot.query_fingerprint:
        return f"fingerprint:{snapshot.query_fingerprint}"
    return f"snapshot:{snapshot.snapshot_id}"
