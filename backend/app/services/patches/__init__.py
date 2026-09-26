"""Automatic migration patch proposal generation.

A generated patch is a reviewable proposal. It is never applied by this
module. Future apply → rescan → verify, CI attachment, and optional PR
creation are intentionally not implemented here.
"""

from app.services.patches.generator import generate_proposal
from app.services.patches.store import latest_proposal, save_proposal

__all__ = ["generate_proposal", "latest_proposal", "save_proposal"]
