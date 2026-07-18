"""
BugKit v4 — Workflow Replay Engine

Records multi-step HTTP flows then replays them in modified order to
detect business logic bugs:
  • skipped mandatory steps
  • out-of-order execution
  • duplicate / replay of one-time steps
  • state confusion after cancel/downgrade
"""
from __future__ import annotations

import json
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.session import BugKitSession
from core import logger
from db import queries


# ── Step representation ────────────────────────────────────────────────

@dataclass
class WorkflowStep:
    name:    str
    method:  str
    url:     str
    headers: Dict[str, str]     = field(default_factory=dict)
    body:    Optional[str]      = None          # JSON string
    params:  Dict[str, str]     = field(default_factory=dict)
    note:    str                = ""

    def to_dict(self) -> dict:
        return {
            "name":    self.name,
            "method":  self.method,
            "url":     self.url,
            "headers": self.headers,
            "body":    self.body,
            "params":  self.params,
            "note":    self.note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WorkflowStep":
        return cls(
            name    = d["name"],
            method  = d["method"],
            url     = d["url"],
            headers = d.get("headers", {}),
            body    = d.get("body"),
            params  = d.get("params", {}),
            note    = d.get("note", ""),
        )


@dataclass
class StepResult:
    step:         WorkflowStep
    status_code:  Optional[int]
    body_snippet: str = ""
    elapsed_ms:   float = 0.0
    error:        str = ""
    success:      bool = False

    def to_dict(self) -> dict:
        return {
            "step":        self.step.name,
            "status":      self.status_code,
            "snippet":     self.body_snippet[:200],
            "elapsed_ms":  round(self.elapsed_ms, 1),
            "success":     self.success,
        }


@dataclass
class ReplayResult:
    scenario:   str
    steps:      List[StepResult] = field(default_factory=list)
    is_anomaly: bool             = False
    note:       str              = ""

    @property
    def succeeded_count(self) -> int:
        return sum(1 for s in self.steps if s.success)

    @property
    def all_succeeded(self) -> bool:
        return all(s.success for s in self.steps)


# ── Replay Engine ──────────────────────────────────────────────────────

class ReplayEngine:
    """
    Record and replay multi-step HTTP workflows.

    Typical usage:
        engine = ReplayEngine(session)
        engine.record_step("signup",  "POST", "https://…/signup",  body=…)
        engine.record_step("verify",  "POST", "https://…/verify",  body=…)
        engine.record_step("upgrade", "POST", "https://…/upgrade", body=…)
        engine.save("checkout-flow", target_id=1)

        # Later
        results = engine.run_all_scenarios(steps, target_id=1)
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session      = session
        self._steps:      List[WorkflowStep] = []

    # ── Recording ──────────────────────────────────────────────────────

    def record_step(
        self,
        name:    str,
        method:  str,
        url:     str,
        headers: dict = None,
        body:    Any  = None,
        params:  dict = None,
        note:    str  = "",
    ) -> None:
        body_str = json.dumps(body) if body and not isinstance(body, str) else body
        step = WorkflowStep(
            name    = name,
            method  = method.upper(),
            url     = url,
            headers = headers or {},
            body    = body_str,
            params  = params or {},
            note    = note,
        )
        self._steps.append(step)
        logger.ok(f"Recorded step [{len(self._steps)}]: {name}  {method} {url}")

    def clear(self) -> None:
        self._steps = []

    def save(self, workflow_name: str, target_id: int, description: str = "") -> None:
        queries.save_workflow(
            target_id   = target_id,
            name        = workflow_name,
            steps       = [s.to_dict() for s in self._steps],
            description = description,
        )
        logger.ok(f"Workflow '{workflow_name}' saved ({len(self._steps)} steps).")

    @classmethod
    def load(cls, session: BugKitSession, target_id: int,
             workflow_name: str) -> "ReplayEngine":
        engine = cls(session)
        wf = queries.get_workflow(target_id, workflow_name)
        if not wf:
            raise ValueError(f"Workflow '{workflow_name}' not found.")
        engine._steps = [WorkflowStep.from_dict(d) for d in wf.step_list]
        logger.ok(f"Loaded workflow '{workflow_name}' ({len(engine._steps)} steps).")
        return engine

    # ── Execution helpers ──────────────────────────────────────────────

    def _run_step(self, step: WorkflowStep) -> StepResult:
        kwargs: dict = {}
        if step.body:
            try:
                kwargs["json"] = json.loads(step.body)
            except Exception:
                kwargs["data"] = step.body
        if step.params:
            kwargs["params"] = step.params
        if step.headers:
            kwargs["headers"] = step.headers

        t0 = time.time()
        resp = self.session.request(step.method, step.url, **kwargs)
        elapsed = (time.time() - t0) * 1000

        if resp is None:
            return StepResult(step=step, status_code=None,
                              elapsed_ms=elapsed, error="no response")
        success = resp.status_code < 400
        return StepResult(
            step         = step,
            status_code  = resp.status_code,
            body_snippet = resp.text[:300],
            elapsed_ms   = elapsed,
            success      = success,
        )

    def _run_sequence(
        self, steps: List[WorkflowStep], label: str
    ) -> ReplayResult:
        result = ReplayResult(scenario=label)
        logger.info(f"  Running scenario: {label!r}")
        for step in steps:
            sr = self._run_step(step)
            result.steps.append(sr)
            icon = "✔" if sr.success else "✖"
            logger.info(
                f"    {icon} {step.name:<24} "
                f"HTTP {sr.status_code or '---'}  ({sr.elapsed_ms:.0f}ms)"
            )
        return result

    # ── Scenario generators ────────────────────────────────────────────

    def run_happy_path(self) -> ReplayResult:
        """Run steps in recorded order — establish baseline."""
        return self._run_sequence(self._steps, "happy_path")

    def run_skip_step(self, skip_index: int) -> ReplayResult:
        """
        Skip one step. If the scenario still succeeds → business logic bug.
        """
        steps = [s for i, s in enumerate(self._steps) if i != skip_index]
        skipped = self._steps[skip_index].name
        result = self._run_sequence(steps, f"skip[{skipped}]")
        if result.all_succeeded:
            result.is_anomaly = True
            result.note = (
                f"Skipping mandatory step '{skipped}' did not break the flow. "
                "The server accepted the sequence without it."
            )
        return result

    def run_reorder(self, new_order: List[int]) -> ReplayResult:
        """Replay steps in a different order. Anomaly = server accepts wrong order."""
        steps = [self._steps[i] for i in new_order]
        label = "reorder[" + "→".join(str(i) for i in new_order) + "]"
        result = self._run_sequence(steps, label)
        if result.all_succeeded:
            result.is_anomaly = True
            result.note = "Server accepted steps in wrong order."
        return result

    def run_duplicate_step(self, step_index: int) -> ReplayResult:
        """Send a step twice. Useful for coupon/action replay bugs."""
        step  = self._steps[step_index]
        steps = list(self._steps) + [deepcopy(step)]
        result = self._run_sequence(steps, f"duplicate[{step.name}]")
        # Anomaly: duplicate succeeded (2nd run returned 2xx)
        duplicate_result = result.steps[-1]
        if duplicate_result.success:
            result.is_anomaly = True
            result.note = (
                f"Step '{step.name}' succeeded when replayed a second time. "
                "One-time actions may not be properly guarded."
            )
        return result

    def run_all_scenarios(self) -> List[ReplayResult]:
        """
        Run all automatic test scenarios and return the full list.
        Saves findings for anomalous results.
        """
        n = len(self._steps)
        results: List[ReplayResult] = []

        # Happy path baseline
        hp = self.run_happy_path()
        results.append(hp)
        if not hp.all_succeeded:
            logger.warn("Happy path itself failed — skipping mutation scenarios.")
            return results

        # Skip each step
        for i in range(n):
            r = self.run_skip_step(i)
            results.append(r)
            if r.is_anomaly:
                logger.warn(f"  ⚑ Anomaly: {r.note}")

        # Duplicate each step
        for i in range(n):
            r = self.run_duplicate_step(i)
            results.append(r)
            if r.is_anomaly:
                logger.warn(f"  ⚑ Anomaly: {r.note}")

        # Reverse order
        if n > 1:
            r = self.run_reorder(list(range(n - 1, -1, -1)))
            results.append(r)
            if r.is_anomaly:
                logger.warn(f"  ⚑ Anomaly: {r.note}")

        return results

    def save_findings(
        self,
        results:   List[ReplayResult],
        target_id: int,
    ) -> int:
        count = 0
        for r in results:
            if not r.is_anomaly:
                continue
            step_summary = "\n".join(
                f"  {'✔' if s.success else '✖'} {s.step.name} → HTTP {s.status_code}"
                for s in r.steps
            )
            queries.save_finding(
                target_id  = target_id,
                module     = "workflows",
                title      = f"Business Logic Flaw — {r.scenario}",
                severity   = "HIGH",
                confidence = "high",
                url        = self._steps[0].url if self._steps else "",
                detail     = r.note,
                evidence   = f"Scenario: {r.scenario}\n\nSteps:\n{step_summary}",
                impact     = (
                    "Business logic bypass. Attacker can reach privileged "
                    "application states by manipulating step sequences."
                ),
                remediation = (
                    "Implement server-side state machine validation. "
                    "Do not rely on the client to enforce step order. "
                    "Track completed steps per-session in server state."
                ),
                cwe  = "CWE-841",
                cvss = 7.5,
                tags = ["business-logic", "workflow", "replay"],
            )
            count += 1
        return count
