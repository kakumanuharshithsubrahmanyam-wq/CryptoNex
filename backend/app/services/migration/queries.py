"""Migration and blast-radius reads over a stored scan."""

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.services.intelligence.snapshot import ScanSnapshot, load_snapshot
from app.services.migration.blast_radius import blast_radius
from app.services.migration.planner import list_plans, plan_finding


def migrations(session: Session, scan: Scan) -> dict:
    return list_plans(load_snapshot(session, scan))


def migration_for_finding(session: Session, scan: Scan, finding_id: int) -> dict:
    snapshot = load_snapshot(session, scan)
    return plan_finding(snapshot, snapshot.finding(finding_id))


def custom_migration_plan(session: Session, scan: Scan, finding_id: int, replacement: str | None) -> dict:
    snapshot = load_snapshot(session, scan)
    return plan_finding(snapshot, snapshot.finding(finding_id), selected_replacement=replacement)


def finding_blast_radius(session: Session, scan: Scan, finding_id: int) -> dict:
    snapshot = load_snapshot(session, scan)
    finding = snapshot.finding(finding_id)
    radius = blast_radius(snapshot.graph, finding.id, finding)
    return {
        "scan_id": scan.id,
        "finding_id": finding.id,
        **radius,
    }


def snapshot_or_load(session: Session, scan: Scan, snapshot: ScanSnapshot | None = None) -> ScanSnapshot:
    return snapshot or load_snapshot(session, scan)
