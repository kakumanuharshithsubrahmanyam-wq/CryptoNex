"""Request models for migration, AI, PQC, and policy endpoints."""

from pydantic import BaseModel, Field


class MigrationPlanRequest(BaseModel):
    finding_id: int
    replacement: str | None = None


class WhatIfRequest(BaseModel):
    finding_id: int
    replacement: str = Field(..., min_length=1, max_length=64)
    mode: str = Field(default="hybrid", min_length=1, max_length=32)


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)


class ArchitectRequest(BaseModel):
    question: str | None = Field(default=None, max_length=2000)


class RootCauseRequest(BaseModel):
    finding_id: int | None = None


class PolicyCheckRequest(BaseModel):
    policy_yaml: str | None = Field(default=None, max_length=20000)
