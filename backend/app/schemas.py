from pydantic import BaseModel, Field, ConfigDict
from typing import Literal

Criticality = Literal["low", "medium", "high", "critical"]
Status = Literal["open", "in_progress", "resolved"]

class AssetIn(BaseModel):
    asset_key: str = Field(min_length=1, max_length=120)
    hostname: str = Field(min_length=1, max_length=255)
    environment: str = Field(default="unknown", max_length=80)
    criticality: Criticality = "medium"
    internet_exposed: bool = False

class VulnerabilityIn(BaseModel):
    finding_key: str = Field(min_length=1, max_length=160)
    asset_key: str = Field(min_length=1, max_length=120)
    cve_id: str | None = Field(default=None, max_length=40)
    title: str = Field(min_length=1, max_length=255)
    cvss: float = Field(default=0.0, ge=0, le=10)
    exploit_available: bool = False
    status: Status = "open"
    description: str = Field(default="", max_length=4000)

class ImportPayload(BaseModel):
    assets: list[AssetIn] = []
    vulnerabilities: list[VulnerabilityIn] = []

class StatusUpdate(BaseModel):
    status: Status
    note: str = Field(default="", max_length=500)

class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_key: str
    hostname: str
    environment: str
    criticality: str
    internet_exposed: bool

class FindingOut(BaseModel):
    id: int
    finding_key: str
    cve_id: str | None
    title: str
    cvss: float
    exploit_available: bool
    status: str
    description: str
    asset_key: str
    hostname: str
    criticality: str
    internet_exposed: bool
    risk_score: int
    risk_factors: list[str]
