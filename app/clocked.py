"""Thin async client for the Clocked API (https://clocked.rezolve.ai/docs).

All nine endpoints + /pipeline. Auth: Bearer key. Every request carries a fresh
Idempotency-Key, so retries never double-bill.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

import httpx

BASE_URL = os.getenv("CLOCKED_BASE_URL", "https://clocked.rezolve.ai/clocked")
ENDPOINTS = {"decide", "extract", "fill", "pii", "injection", "script",
             "grounding", "compare", "rerank", "pipeline"}


class ClockedError(RuntimeError):
    def __init__(self, endpoint: str, status: int, body: str):
        super().__init__(f"/{endpoint} -> {status}: {body[:300]}")
        self.endpoint, self.status, self.body = endpoint, status, body


class Clocked:
    def __init__(self, api_key: str | None = None, timeout: float = 30.0, max_retries: int = 3):
        self.api_key = api_key or os.getenv("CLOCKED_API_KEY", "")
        if not self.api_key:
            raise RuntimeError("CLOCKED_API_KEY missing - copy .env.example to .env")
        self.max_retries = max_retries
        # The hackathon code grants 4 concurrent requests; respect it.
        self._sem = asyncio.Semaphore(int(os.getenv("CLOCKED_CONCURRENCY", "4")))
        self._http = httpx.AsyncClient(timeout=timeout)
        self.calls: list[dict[str, Any]] = []  # per-run audit log (endpoint, ms, credits)

    async def close(self) -> None:
        await self._http.aclose()

    def reset_log(self) -> list[dict[str, Any]]:
        log, self.calls = self.calls, []
        return log

    async def call(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        assert endpoint in ENDPOINTS, endpoint
        idem = str(uuid.uuid4())  # same key across retries of one logical call
        headers = {"Authorization": f"Bearer {self.api_key}", "Idempotency-Key": idem,
                   "Content-Type": "application/json"}
        delay = 0.5
        async with self._sem:
            for attempt in range(self.max_retries + 1):
                t0 = time.perf_counter()
                r = await self._http.post(f"{BASE_URL}/{endpoint}", json=body, headers=headers)
                if r.status_code < 400:
                    data = r.json()
                    self.calls.append({
                        "endpoint": endpoint,
                        "wall_ms": round((time.perf_counter() - t0) * 1000),
                        "ms": (data.get("timing") or {}).get("total_ms"),
                        "credits": r.headers.get("x-clocked-credits") or r.headers.get("x-credits-used"),
                    })
                    return data
                if r.status_code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    ra = r.headers.get("retry-after")
                    await asyncio.sleep(float(ra) if ra and ra.isdigit() else delay)
                    delay *= 2
                    continue
                raise ClockedError(endpoint, r.status_code, r.text)
        raise ClockedError(endpoint, 0, "unreachable")

    # convenience wrappers
    async def decide(self, **b): return await self.call("decide", b)
    async def extract(self, **b): return await self.call("extract", b)
    async def fill(self, **b): return await self.call("fill", b)
    async def pii(self, **b): return await self.call("pii", b)
    async def injection(self, **b): return await self.call("injection", b)
    async def script(self, **b): return await self.call("script", b)
    async def grounding(self, **b): return await self.call("grounding", b)
    async def compare(self, **b): return await self.call("compare", b)
    async def rerank(self, **b): return await self.call("rerank", b)
    async def pipeline(self, **b): return await self.call("pipeline", b)

