from __future__ import annotations
from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    domains: Mapped[list["CompanyDomain"]] = relationship(
        back_populates="company", cascade="all, delete-orphan"
    )
    scans: Mapped[list["ScanRun"]] = relationship(
        back_populates="company", cascade="all, delete-orphan"
    )


class CompanyDomain(Base):
    __tablename__ = "company_domains"
    __table_args__ = (
        UniqueConstraint("company_id", "domain", name="uq_company_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)

    company: Mapped["Company"] = relationship(back_populates="domains")


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        UniqueConstraint(
            "company_id", "company_scan_number", name="uq_company_scan_number"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    company_scan_number: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default="running"
    )  # running/success/failed
    notes: Mapped[str | None] = mapped_column(String(255), nullable=True)

    company: Mapped["Company"] = relationship(back_populates="scans")
    artifacts: Mapped[list["ScanArtifact"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"
    __table_args__ = (
        UniqueConstraint("scan_id", "artifact_type", name="uq_scan_artifact_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64))
    json_text: Mapped[str] = mapped_column(Text)

    scan: Mapped["ScanRun"] = relationship(back_populates="artifacts")
