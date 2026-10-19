from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base

def utcnow():
    return datetime.now(timezone.utc)

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(80), default="unknown")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    cve_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    asset: Mapped[Asset] = relationship(back_populates="vulnerabilities")
    history: Mapped[list["StatusHistory"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")

class StatusHistory(Base):
    __tablename__ = "status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"))
    old_status: Mapped[str] = mapped_column(String(24))
    new_status: Mapped[str] = mapped_column(String(24))
    note: Mapped[str] = mapped_column(String(500), default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="history")
