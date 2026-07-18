"""
BugKit v4 — Database Models (SQLAlchemy 2.0 declarative style)
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer,
    String, Text, create_engine, event
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, relationship,
    mapped_column
)


class Base(DeclarativeBase):
    pass


# ── Target ─────────────────────────────────────────────────────────────

class Target(Base):
    __tablename__ = "targets"

    id:         Mapped[int]           = mapped_column(Integer, primary_key=True)
    domain:     Mapped[str]           = mapped_column(String(256), unique=True, index=True)
    base_url:   Mapped[Optional[str]] = mapped_column(String(512))
    scope:      Mapped[Optional[str]] = mapped_column(Text)          # JSON list
    tech:       Mapped[Optional[str]] = mapped_column(Text)          # JSON list
    notes:      Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow,
                                                      onupdate=datetime.utcnow)

    identities: Mapped[List["Identity"]]  = relationship("Identity",  back_populates="target", cascade="all,delete")
    endpoints:  Mapped[List["Endpoint"]]  = relationship("Endpoint",  back_populates="target", cascade="all,delete")
    findings:   Mapped[List["Finding"]]   = relationship("Finding",   back_populates="target", cascade="all,delete")
    scans:      Mapped[List["Scan"]]      = relationship("Scan",      back_populates="target", cascade="all,delete")
    snapshots:  Mapped[List["Snapshot"]]  = relationship("Snapshot",  back_populates="target", cascade="all,delete")
    workflows:  Mapped[List["Workflow"]]  = relationship("Workflow",  back_populates="target", cascade="all,delete")

    @property
    def scope_list(self) -> List[str]:
        return json.loads(self.scope) if self.scope else []

    @property
    def tech_list(self) -> List[str]:
        return json.loads(self.tech) if self.tech else []


# ── Identity (encrypted credentials) ──────────────────────────────────

class Identity(Base):
    __tablename__ = "identities"

    id:         Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:  Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    name:       Mapped[str]           = mapped_column(String(128))   # "userA", "admin_candidate"
    role:       Mapped[str]           = mapped_column(String(64), default="user")
    secrets:    Mapped[Optional[str]] = mapped_column(Text)          # Fernet-encrypted JSON
    note:       Mapped[Optional[str]] = mapped_column(Text)
    verified:   Mapped[bool]          = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)

    target: Mapped["Target"] = relationship("Target", back_populates="identities")


# ── Endpoint ───────────────────────────────────────────────────────────

class Endpoint(Base):
    __tablename__ = "endpoints"

    id:          Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:   Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    url:         Mapped[str]           = mapped_column(String(2048), index=True)
    method:      Mapped[str]           = mapped_column(String(16), default="GET")
    params:      Mapped[Optional[str]] = mapped_column(Text)   # JSON list
    auth_required: Mapped[Optional[bool]] = mapped_column(Boolean)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    content_type: Mapped[Optional[str]]= mapped_column(String(128))
    source:      Mapped[Optional[str]] = mapped_column(String(64))  # recon|js|crawl|manual
    first_seen:  Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)
    last_seen:   Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow,
                                                       onupdate=datetime.utcnow)

    target: Mapped["Target"] = relationship("Target", back_populates="endpoints")


# ── Finding ────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id:           Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:    Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    module:       Mapped[str]           = mapped_column(String(64))
    title:        Mapped[str]           = mapped_column(String(512))
    severity:     Mapped[str]           = mapped_column(String(32))   # CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence:   Mapped[str]           = mapped_column(String(16), default="medium")
    url:          Mapped[str]           = mapped_column(String(2048))
    method:       Mapped[Optional[str]] = mapped_column(String(16))
    parameter:    Mapped[Optional[str]] = mapped_column(String(256))
    payload:      Mapped[Optional[str]] = mapped_column(Text)
    evidence:     Mapped[Optional[str]] = mapped_column(Text)
    raw_request:  Mapped[Optional[str]] = mapped_column(Text)
    raw_response: Mapped[Optional[str]] = mapped_column(Text)
    curl_poc:     Mapped[Optional[str]] = mapped_column(Text)
    repro_steps:  Mapped[Optional[str]] = mapped_column(Text)
    detail:       Mapped[Optional[str]] = mapped_column(Text)
    impact:       Mapped[Optional[str]] = mapped_column(Text)
    remediation:  Mapped[Optional[str]] = mapped_column(Text)
    cwe:          Mapped[Optional[str]] = mapped_column(String(32))
    cvss:         Mapped[Optional[float]]= mapped_column(Float)
    tags:         Mapped[Optional[str]] = mapped_column(Text)         # JSON list
    screenshot:   Mapped[Optional[bytes]]= mapped_column(Text)        # base64 PNG
    duplicate_of: Mapped[Optional[int]] = mapped_column(ForeignKey("findings.id"))
    created_at:   Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)

    target: Mapped["Target"] = relationship("Target", back_populates="findings")

    @property
    def tag_list(self) -> List[str]:
        return json.loads(self.tags) if self.tags else []


# ── Scan (run log) ─────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id:         Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:  Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    module:     Mapped[str]           = mapped_column(String(64))
    status:     Mapped[str]           = mapped_column(String(32), default="running")
    findings_n: Mapped[int]           = mapped_column(Integer, default=0)
    started_at: Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)
    ended_at:   Mapped[Optional[datetime]] = mapped_column(DateTime)
    meta:       Mapped[Optional[str]] = mapped_column(Text)   # JSON dict

    target: Mapped["Target"] = relationship("Target", back_populates="scans")


# ── Snapshot (change-detection baseline) ──────────────────────────────

class Snapshot(Base):
    __tablename__ = "snapshots"

    id:         Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:  Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    url:        Mapped[str]           = mapped_column(String(2048))
    sha256:     Mapped[str]           = mapped_column(String(64))
    body_size:  Mapped[int]           = mapped_column(Integer)
    status:     Mapped[int]           = mapped_column(Integer)
    headers:    Mapped[Optional[str]] = mapped_column(Text)   # JSON
    taken_at:   Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)

    target: Mapped["Target"] = relationship("Target", back_populates="snapshots")


# ── Workflow (recorded multi-step flow) ────────────────────────────────

class Workflow(Base):
    __tablename__ = "workflows"

    id:          Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:   Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    name:        Mapped[str]           = mapped_column(String(256))
    description: Mapped[Optional[str]] = mapped_column(Text)
    steps:       Mapped[Optional[str]] = mapped_column(Text)   # JSON list of step dicts
    created_at:  Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)

    target: Mapped["Target"] = relationship("Target", back_populates="workflows")

    @property
    def step_list(self) -> list:
        return json.loads(self.steps) if self.steps else []


# ── Object (tracked ID for IDOR / ownership) ──────────────────────────

class TrackedObject(Base):
    __tablename__ = "objects"

    id:          Mapped[int]           = mapped_column(Integer, primary_key=True)
    target_id:   Mapped[int]           = mapped_column(ForeignKey("targets.id"))
    kind:        Mapped[str]           = mapped_column(String(64))   # user|order|invoice|…
    object_id:   Mapped[str]           = mapped_column(String(256))
    owner:       Mapped[Optional[str]] = mapped_column(String(128))  # identity name
    url:         Mapped[Optional[str]] = mapped_column(String(2048))
    meta:        Mapped[Optional[str]] = mapped_column(Text)         # JSON
    created_at:  Mapped[datetime]      = mapped_column(DateTime, default=datetime.utcnow)


# ── Engine factory ─────────────────────────────────────────────────────

def make_engine(db_path: str):
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    # Enable WAL for concurrent reads
    @event.listens_for(engine, "connect")
    def set_wal(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return engine
