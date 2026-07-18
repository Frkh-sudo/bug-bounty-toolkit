"""
BugKit v4 — Race Condition Engine

Sends concurrent requests to detect TOCTOU and race condition bugs.
Useful for:
  • Coupon/voucher double-redemption
  • Concurrent account actions (balance, credits)
  • One-time token replay
  • Rate limit bypass via burst timing
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


from core.session import BugKitSession
from core import logger
from config import settings


@dataclass
class RaceResult:
    url:          str
    method:       str
    concurrency:  int
    responses:    List[Dict]      = field(default_factory=list)
    is_anomaly:   bool            = False
    anomaly_note: str             = ""

    @property
    def success_count(self) -> int:
        # status is None (not missing) for requests that errored/timed out,
        # so r.get("status", 0) still returns None and `None < 400` raises
        # TypeError. Only count entries that actually have an int status.
        return sum(
            1 for r in self.responses
            if isinstance(r.get("status"), int) and r["status"] < 400
        )

    @property
    def status_distribution(self) -> Dict[Any, int]:
        dist: Dict[Any, int] = {}
        for r in self.responses:
            # Label failed/timed-out requests explicitly instead of a bare
            # None key, which reads ambiguously next to real status codes.
            s = r.get("status") if r.get("status") is not None else "ERR"
            dist[s] = dist.get(s, 0) + 1
        return dist


class RaceEngine:
    """
    Fire N concurrent requests to the same endpoint and look for
    inconsistencies that indicate race conditions.

    Usage:
        engine = RaceEngine(session)
        result = engine.race("POST", "https://…/redeem-coupon",
                             json_body={"code": "SAVE50"},
                             concurrency=10)
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session = session

    def race(
        self,
        method:      str,
        url:         str,
        concurrency: int              = 10,
        json_body:   dict             = None,
        form_data:   dict             = None,
        headers:     dict             = None,
        identity:    Optional[str]    = None,
    ) -> RaceResult:
        """
        Send `concurrency` requests simultaneously using a barrier
        to maximise the chance of overlapping server-side execution.
        """
        logger.section(f"Race Engine  {method} {url}  x{concurrency}")

        result = RaceResult(url=url, method=method, concurrency=concurrency)
        barrier     = threading.Barrier(concurrency)
        lock        = threading.Lock()
        responses:  List[Dict] = []

        def _fire(thread_id: int) -> None:
            kwargs: dict = {}
            if json_body is not None:
                kwargs["json"] = json_body
            if form_data is not None:
                kwargs["data"] = form_data
            if headers:
                kwargs["headers"] = headers

            # Wait until all threads are ready, then fire simultaneously.
            # throttle=False is required here — otherwise every thread
            # serializes through the shared per-session delay lock right
            # after the barrier releases them, turning this back into a
            # sequential trickle and defeating the whole point of a race
            # burst.
            barrier.wait()
            t0   = time.time()
            resp = self.session.request(method, url, identity_name=identity,
                                        capture=False, throttle=False, **kwargs)
            elapsed = (time.time() - t0) * 1000

            entry = {
                "thread":  thread_id,
                # `resp` truthiness is NOT the same as "did we get a
                # response" — requests.Response.__bool__() is False for
                # ANY 4xx/5xx status. For race testing specifically this
                # matters a lot: a server correctly rejecting a duplicate
                # request (e.g. 400 "coupon already used") is a real,
                # meaningful result, not a failure — but `if resp` would
                # record it exactly like a dropped connection, making
                # "properly serialized" indistinguishable from "network
                # error" in every downstream stat.
                "status":  resp.status_code if resp is not None else None,
                "size":    len(resp.content) if resp is not None else 0,
                "elapsed": round(elapsed, 1),
                "snippet": (resp.text[:200] if resp is not None else ""),
            }
            with lock:
                responses.append(entry)

        threads = [
            threading.Thread(target=_fire, args=(i,), daemon=True)
            for i in range(concurrency)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=settings.timeout + 5)

        result.responses = responses

        # ── Anomaly detection ──────────────────────────────────────────
        dist = result.status_distribution
        logger.info(f"Status distribution: {dict(sorted(dist.items()))}")

        # If more than 1 request succeeded on a normally idempotent operation
        if result.success_count > 1:
            result.is_anomaly   = True
            result.anomaly_note = (
                f"{result.success_count}/{concurrency} concurrent requests "
                "returned success. Race condition may allow duplicate action."
            )
            logger.warn(f"⚑ {result.anomaly_note}")

        # Mixed 2xx/4xx in the same burst = inconsistent state guard
        elif len(dist) > 1 and any(s < 400 for s in dist):
            result.is_anomaly   = True
            result.anomaly_note = (
                f"Mixed status codes in race burst: {dist}. "
                "Server state guard may have a window."
            )
            logger.warn(f"⚑ {result.anomaly_note}")
        else:
            logger.ok("No race condition detected in this burst.")

        return result

    def race_all_identities(
        self,
        method:      str,
        url:         str,
        concurrency: int  = 5,
        **kwargs,
    ) -> List[RaceResult]:
        """Fire race bursts as each loaded identity."""
        results: List[RaceResult] = []
        for name in self.session.identity_names:
            r = self.race(method, url, concurrency=concurrency,
                          identity=name, **kwargs)
            results.append(r)
        return results
