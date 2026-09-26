"""Session-facing patch proposal API helpers."""

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.scan import Scan
from app.services.intelligence.snapshot import load_snapshot
from app.services.patches.generator import generate_proposal
from app.services.patches.store import latest_proposal, save_proposal


def create_finding_patch(
    session: Session,
    scan: Scan,
    finding_id: int,
    settings: Settings,
    replacement: str | None = None,
    mode: str = "minimal",
) -> dict:
    snapshot = load_snapshot(session, scan)
    finding = snapshot.finding(finding_id)
    proposal = generate_proposal(snapshot, finding, settings, replacement, mode)
    stored = save_proposal(session, proposal)
    return stored.as_dict()


def read_finding_patch(session: Session, scan: Scan, finding_id: int) -> dict:
    snapshot = load_snapshot(session, scan)
    snapshot.finding(finding_id)
    return latest_proposal(session, scan.id, finding_id).as_dict()
