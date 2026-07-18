"""
BugKit v4 — Database Query Layer

All DB interaction goes through this module.
Callers import `get_db` to get a context-managed session.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional

from sqlalchemy.orm import Session

from config import settings
from db.models import (
    Endpoint, Finding, Identity, Scan, Snapshot,
    Target, TrackedObject, Workflow, make_engine
)


# ── Engine singleton ───────────────────────────────────────────────────

_engine = None
_migrated = False


def _get_engine():
    global _engine, _migrated
    if _engine is None:
        Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
        # Run migrations before creating the SQLAlchemy engine
        if not _migrated:
            from db.migrations import migrate
            migrate(str(settings.db_path))
            _migrated = True
        _engine = make_engine(str(settings.db_path))
    return _engine


@contextmanager
def get_db() -> Generator[Session, None, None]:
    # expire_on_commit=False is required here: every function in this file
    # returns ORM objects (Target, Finding, etc.) to callers OUTSIDE this
    # `with` block. With the default expire_on_commit=True, the commit()
    # below marks all attributes on those objects as stale, and the
    # session.close() that follows means there's nothing left to reload
    # them from — so ANY attribute access after return raises
    # DetachedInstanceError. This isn't a rare edge case: cli.py's
    # queries.get_target(target) → t.scope_list is exactly this pattern,
    # so it broke on essentially every real invocation once a target
    # already existed in the DB. expire_on_commit=False keeps the
    # already-loaded values usable after the session is gone.
    with Session(_get_engine(), expire_on_commit=False) as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise


# ── Target ─────────────────────────────────────────────────────────────

def upsert_target(domain: str, base_url: str = "", scope: list = None,
                  notes: str = "") -> Target:
    with get_db() as db:
        t = db.query(Target).filter_by(domain=domain).first()
        if not t:
            t = Target(domain=domain)
            db.add(t)
        t.base_url = base_url or t.base_url
        if scope is not None:
            t.scope = json.dumps(scope)
        t.notes = notes or t.notes
        db.flush()
        db.refresh(t)
        return t


def get_target(domain: str) -> Optional[Target]:
    with get_db() as db:
        return db.query(Target).filter_by(domain=domain).first()


def list_targets() -> List[Target]:
    with get_db() as db:
        return db.query(Target).order_by(Target.domain).all()


def delete_target(domain: str) -> bool:
    with get_db() as db:
        t = db.query(Target).filter_by(domain=domain).first()
        if t:
            db.delete(t)
            return True
        return False


# ── Identity ───────────────────────────────────────────────────────────

def save_identity(target_id: int, name: str, role: str,
                  secrets: str, note: str = "") -> Identity:
    with get_db() as db:
        existing = db.query(Identity).filter_by(
            target_id=target_id, name=name).first()
        if existing:
            existing.role    = role
            existing.secrets = secrets
            existing.note    = note
            db.flush()
            db.refresh(existing)
            return existing
        ident = Identity(target_id=target_id, name=name,
                         role=role, secrets=secrets, note=note)
        db.add(ident)
        db.flush()
        db.refresh(ident)
        return ident


def get_identities(target_id: int) -> List[Identity]:
    with get_db() as db:
        return (db.query(Identity)
                  .filter_by(target_id=target_id)
                  .order_by(Identity.name)
                  .all())


def delete_identity(target_id: int, name: str) -> bool:
    with get_db() as db:
        ident = db.query(Identity).filter_by(
            target_id=target_id, name=name).first()
        if ident:
            db.delete(ident)
            return True
        return False


def mark_identity_verified(target_id: int, name: str) -> None:
    with get_db() as db:
        ident = db.query(Identity).filter_by(
            target_id=target_id, name=name).first()
        if ident:
            ident.verified = True


# ── Endpoint ───────────────────────────────────────────────────────────

def upsert_endpoint(target_id: int, url: str, method: str = "GET",
                    params: list = None, status_code: int = None,
                    auth_required: bool = None, source: str = "recon",
                    content_type: str = None) -> Endpoint:
    with get_db() as db:
        ep = db.query(Endpoint).filter_by(
            target_id=target_id, url=url, method=method).first()
        if not ep:
            ep = Endpoint(target_id=target_id, url=url, method=method)
            db.add(ep)
        if params is not None:
            ep.params = json.dumps(params)
        if status_code is not None:
            ep.status_code = status_code
        if auth_required is not None:
            ep.auth_required = auth_required
        if content_type:
            ep.content_type = content_type
        ep.source    = source
        ep.last_seen = datetime.utcnow()
        db.flush()
        db.refresh(ep)
        return ep


def get_endpoints(target_id: int, source: str = None) -> List[Endpoint]:
    with get_db() as db:
        q = db.query(Endpoint).filter_by(target_id=target_id)
        if source:
            q = q.filter_by(source=source)
        return q.order_by(Endpoint.url).all()


# ── Finding ────────────────────────────────────────────────────────────

def save_finding(
    target_id:    int,
    module:       str,
    title:        str,
    severity:     str,
    url:          str,
    confidence:   str = "medium",
    method:       str = "GET",
    parameter:    str = "",
    payload:      str = "",
    evidence:     str = "",
    raw_request:  str = "",
    raw_response: str = "",
    curl_poc:     str = "",
    repro_steps:  str = "",
    detail:       str = "",
    impact:       str = "",
    remediation:  str = "",
    cwe:          str = "",
    cvss:         float = 0.0,
    tags:         list  = None,
) -> Finding:
    with get_db() as db:
        f = Finding(
            target_id    = target_id,
            module       = module,
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            method       = method,
            parameter    = parameter,
            payload      = payload,
            evidence     = evidence,
            raw_request  = raw_request,
            raw_response = raw_response,
            curl_poc     = curl_poc,
            repro_steps  = repro_steps,
            detail       = detail,
            impact       = impact,
            remediation  = remediation,
            cwe          = cwe,
            cvss         = cvss,
            tags         = json.dumps(tags or []),
        )
        db.add(f)
        db.flush()
        db.refresh(f)
        return f


def get_findings(
    target_id: int = None,
    module:    str = None,
    severity:  str = None,
    min_confidence: str = None,
) -> List[Finding]:
    with get_db() as db:
        q = db.query(Finding)
        if target_id:
            q = q.filter_by(target_id=target_id)
        if module:
            q = q.filter_by(module=module)
        if severity:
            q = q.filter_by(severity=severity.upper())
        return q.order_by(Finding.severity, Finding.created_at.desc()).all()


# ── Scan log ───────────────────────────────────────────────────────────

def start_scan(target_id: int, module: str, meta: dict = None) -> Scan:
    with get_db() as db:
        s = Scan(target_id=target_id, module=module,
                 meta=json.dumps(meta or {}))
        db.add(s)
        db.flush()
        db.refresh(s)
        return s


def finish_scan(scan_id: int, findings_n: int, status: str = "done") -> None:
    with get_db() as db:
        s = db.query(Scan).filter_by(id=scan_id).first()
        if s:
            s.status     = status
            s.findings_n = findings_n
            s.ended_at   = datetime.utcnow()


# ── Snapshot ───────────────────────────────────────────────────────────

def save_snapshot(target_id: int, url: str, sha256: str,
                  body_size: int, status: int,
                  headers: dict = None) -> Snapshot:
    with get_db() as db:
        snap = Snapshot(
            target_id = target_id,
            url       = url,
            sha256    = sha256,
            body_size = body_size,
            status    = status,
            headers   = json.dumps(headers or {}),
        )
        db.add(snap)
        db.flush()
        db.refresh(snap)
        return snap


def get_latest_snapshot(target_id: int, url: str) -> Optional[Snapshot]:
    with get_db() as db:
        return (db.query(Snapshot)
                  .filter_by(target_id=target_id, url=url)
                  .order_by(Snapshot.taken_at.desc())
                  .first())


# ── Workflow ───────────────────────────────────────────────────────────

def save_workflow(target_id: int, name: str, steps: list,
                  description: str = "") -> Workflow:
    with get_db() as db:
        wf = db.query(Workflow).filter_by(
            target_id=target_id, name=name).first()
        if not wf:
            wf = Workflow(target_id=target_id, name=name)
            db.add(wf)
        wf.steps       = json.dumps(steps)
        wf.description = description
        db.flush()
        db.refresh(wf)
        return wf


def get_workflow(target_id: int, name: str) -> Optional[Workflow]:
    with get_db() as db:
        return db.query(Workflow).filter_by(
            target_id=target_id, name=name).first()


def list_workflows(target_id: int) -> List[Workflow]:
    with get_db() as db:
        return db.query(Workflow).filter_by(target_id=target_id).all()


# ── Tracked objects ────────────────────────────────────────────────────

def track_object(target_id: int, kind: str, object_id: str,
                 owner: str = "", url: str = "", meta: dict = None) -> TrackedObject:
    with get_db() as db:
        obj = TrackedObject(
            target_id = target_id,
            kind      = kind,
            object_id = object_id,
            owner     = owner,
            url       = url,
            meta      = json.dumps(meta or {}),
        )
        db.add(obj)
        db.flush()
        db.refresh(obj)
        return obj


def get_objects(target_id: int, kind: str = None) -> List[TrackedObject]:
    with get_db() as db:
        q = db.query(TrackedObject).filter_by(target_id=target_id)
        if kind:
            q = q.filter_by(kind=kind)
        return q.all()
