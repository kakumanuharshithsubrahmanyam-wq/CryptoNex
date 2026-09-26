"""CBOM, inventory, and graph API models."""

from typing import Any

from pydantic import BaseModel, Field


class CbomResponse(BaseModel):
    schema_version: str
    schema_name: str
    scan_id: int
    project_id: int
    generated_at: str
    summary: dict[str, int]
    components: list[dict[str, Any]]
    relationships: list[dict[str, Any]]


class InventoryResponse(BaseModel):
    scan_id: int
    algorithms: dict[str, int] = Field(default_factory=dict)
    libraries: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    certificates: int = 0
    protocols: dict[str, int] = Field(default_factory=dict)
    cipher_suites: list[str] = Field(default_factory=list)
    source_locations: list[str] = Field(default_factory=list)


class GraphResponse(BaseModel):
    scan_id: int
    project_id: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    summary: dict[str, Any]
