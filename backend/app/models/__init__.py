"""ORM models registered with SQLAlchemy metadata."""

from app.models.artifact import SecurityArtifact
from app.models.cbom import Cbom, CbomComponent, CbomRelationship
from app.models.dependency import Dependency, DependencyRelationship
from app.models.patch import MigrationPatchProposal
from app.models.project import Project
from app.models.scan import CryptoFinding, Scan
from app.models.verification import MigrationVerification

__all__ = [
    "Cbom",
    "CbomComponent",
    "CbomRelationship",
    "CryptoFinding",
    "Dependency",
    "DependencyRelationship",
    "MigrationPatchProposal",
    "MigrationVerification",
    "Project",
    "Scan",
    "SecurityArtifact",
]
