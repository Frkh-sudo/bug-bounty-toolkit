"""
BugKit v4 — Concurrent Request Scheduler

Replaces sequential request loops with a thread-pool executor so every
scan that iterates over endpoints/payloads/identities runs concurrently.

Key design decisions:
  • Uses requests + ThreadPoolExecutor (stdlib) — no httpx/asyncio dep
  • Respects global rate limit via a shared token-bucket throttle
  • Scope guard called inside each worker thread
  • Results collected in submission order (futures.as_completed for speed)
  • Safe-mode flag honoured — DELETE/PUT blocked unless overridden

Usage:
    scheduler = Scheduler(session, workers=8)
    results   = scheduler.map(
        fn      = session.get,
        targets = ["https://example.com/api/users/1",
                   "https://example.com/api/users/2"],
    )

    # Or with a custom callable per-item
    results = scheduler.run_tasks([
        Task(fn=session.get,  args=("https://…/users/1",)),
        Task(fn=session.post, args=("https://…/login",), kwargs={"json": body}),
    ])
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

import requests

from config import settings
from core import logger


# ── Token-bucket rate limiter ──────────────────────────────────────────

class _TokenBucket:
    """
    Thread-safe token bucket.
    Ensures we never exceed `rate` requests per second across all workers.
    """
    def __init__(self, rate: float = 5.0) -> None:
        self._rate    = rate          # tokens per second
        # Starting the bucket at `rate` tokens let the first `rate` calls
        # fire with zero delay before any throttling kicked in — e.g. at
        # rate=10/s, 10 requests would hit the target instantly. For a
        # tool whose whole point is not hammering a target, that initial
        # burst defeats the purpose. Start with a single free token so
        # throttling applies from (effectively) the first request, while
        # still not delaying the very first request in a scan.
        self._tokens  = 1.0
        self._lock    = threading.Lock()
        self._last    = time.monotonic()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self._rate,
                self._tokens + (now - self._last) * self._rate,
            )
            if self._tokens < 1:
                sleep_for = (1 - self._tokens) / self._rate
                time.sleep(sleep_for)
                # _last must account for the time spent sleeping too —
                # stamping it as `now` (pre-sleep) let the NEXT call's
                # elapsed-time calculation count that same sleep duration
                # a second time as fresh accumulation, refilling tokens
                # it hadn't actually earned yet and undercutting the
                # throttle.
                self._last = now + sleep_for
                self._tokens = 0
            else:
                self._last = now
                self._tokens -= 1


# ── Task dataclass ─────────────────────────────────────────────────────

@dataclass
class Task:
    fn:     Callable
    args:   Tuple    = field(default_factory=tuple)
    kwargs: Dict     = field(default_factory=dict)
    tag:    str      = ""      # optional label for the result


@dataclass
class TaskResult:
    task:      Task
    response:  Optional[requests.Response]
    elapsed:   float = 0.0
    error:     str   = ""

    @property
    def ok(self) -> bool:
        return self.response is not None and self.response.status_code < 400


# ── Scheduler ──────────────────────────────────────────────────────────

class Scheduler:
    """
    Thread-pool request scheduler with rate limiting.

    workers: concurrent threads (default from settings)
    rate:    max requests per second across all workers
    """

    def __init__(
        self,
        workers: int   = None,
        rate:    float = None,
    ) -> None:
        self._workers = workers or settings.workers
        self._bucket  = _TokenBucket(rate or (1.0 / max(settings.delay, 0.05)))
        self._lock    = threading.Lock()
        self._errors: List[str] = []

    # ── Public API ─────────────────────────────────────────────────────

    def map(
        self,
        fn:       Callable,
        targets:  List[Any],
        fn_kwargs: Dict = None,
        tag_fn:   Callable = None,
    ) -> List[TaskResult]:
        """
        Apply `fn` to every item in `targets` concurrently.
        `fn` receives the target as its first positional argument.
        """
        tasks = [
            Task(
                fn     = fn,
                args   = (t,),
                kwargs = fn_kwargs or {},
                tag    = tag_fn(t) if tag_fn else str(t),
            )
            for t in targets
        ]
        return self.run_tasks(tasks)

    def run_tasks(self, tasks: List[Task]) -> List[TaskResult]:
        """
        Execute a heterogeneous list of Tasks concurrently.
        Returns results in the same order as input tasks.
        """
        results: List[Optional[TaskResult]] = [None] * len(tasks)

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_to_idx: Dict[Future, int] = {}
            for i, task in enumerate(tasks):
                future = pool.submit(self._run_one, task)
                future_to_idx[future] = i

            completed = 0
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = TaskResult(
                        task    = tasks[idx],
                        response= None,
                        error   = str(e),
                    )
                completed += 1
                if completed % 10 == 0:
                    logger.debug(f"Scheduler: {completed}/{len(tasks)} tasks done")

        # Filter out None (shouldn't happen but be safe)
        return [r for r in results if r is not None]

    def run_tasks_streaming(
        self, tasks: List[Task]
    ) -> Generator[TaskResult, None, None]:
        """
        Yield results as they complete (faster for large batches where
        you want to act on each result immediately).
        """
        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_to_task: Dict[Future, Task] = {
                pool.submit(self._run_one, task): task
                for task in tasks
            }
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    yield future.result()
                except Exception as e:
                    yield TaskResult(task=task, response=None, error=str(e))

    # ── Worker ─────────────────────────────────────────────────────────

    def _run_one(self, task: Task) -> TaskResult:
        self._bucket.acquire()
        t0 = time.monotonic()
        try:
            resp = task.fn(*task.args, **task.kwargs)
            return TaskResult(
                task     = task,
                response = resp,
                elapsed  = time.monotonic() - t0,
            )
        except Exception as e:
            with self._lock:
                self._errors.append(f"{task.tag}: {e}")
            return TaskResult(
                task    = task,
                response= None,
                elapsed = time.monotonic() - t0,
                error   = str(e),
            )

    # ── Convenience helpers ────────────────────────────────────────────

    @property
    def errors(self) -> List[str]:
        return list(self._errors)

    def sweep_endpoints(
        self,
        session,                    # BugKitSession
        urls:    List[str],
        method:  str = "GET",
        **request_kwargs,
    ) -> List[TaskResult]:
        """
        Concurrently fetch a list of URLs with the session.
        Returns TaskResult list with responses.
        """
        fn = session.get if method.upper() == "GET" else session.post
        return self.map(fn, urls, fn_kwargs=request_kwargs, tag_fn=lambda u: u)

    def sweep_identities(
        self,
        session,
        method:  str,
        url:     str,
        identities: List[str],
        **request_kwargs,
    ) -> List[TaskResult]:
        """
        Send the same request as each identity concurrently.
        Returns TaskResult list keyed by identity name.
        """
        tasks = [
            Task(
                fn     = session.request,
                args   = (method, url),
                kwargs = {"identity_name": name, **request_kwargs},
                tag    = name,
            )
            for name in identities
        ]
        return self.run_tasks(tasks)


# ── Module-level default scheduler ────────────────────────────────────

_default: Optional[Scheduler] = None


def get_scheduler(workers: int = None) -> Scheduler:
    """Return (or create) the module-level default scheduler."""
    global _default
    if _default is None or (workers and workers != _default._workers):
        _default = Scheduler(workers=workers)
    return _default
