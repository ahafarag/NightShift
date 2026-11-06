"""Offline tests: a fake client returns documented response shapes, so the
engine's gating logic is tested without spending credits."""
import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import engine, main

FIX = Path(__file__).resolve().parent.parent / "app" / "fixtures"


class FakeClocked:
    def __init__(self, tainted=False, ungrounded=False):
        self.tainted, self.ungrounded, self.calls = tainted, ungrounded, []

    def reset_log(self):
        log, self.calls = self.calls, []
        return log

    async def close(self):
        pass

    def _log(self, ep):
        self.calls.append({"endpoint": ep, "ms": 1, "credits": 1})

    async def pipeline(self, text, steps, **_):
        self._log("pipeline")
        masked = " ".join("<EMAIL>" if "@" in w else w for w in text.split(" "))
        pii = {"entities": [{"type": "email", "value": "x", "start": 0, "end": 5, "confidence": 1}],
               "anonymized_text": masked}
        inj = {"injection": 0.97 if self.tainted else 0.01, "threshold": 0.5,
               "verdict": "injection" if self.tainted else "benign", "category": "instruction override",
               "evidence": [{"start": 10, "end": 20, "confidence": 1}] if self.tainted else []}
        return {"steps": [{"result": pii}, {"result": inj}],
                "stopped": {"step": 1} if self.tainted else None}

    async def pii(self, text, **_):
        self._log("pii")
        return {"entities": [], "anonymized_text": text}

    async def extract(self, text, fields, **_):
        self._log("extract")
        return {"fields": {"service": {"value": "checkout-api", "start": 0, "end": 3},
                           "host": {"value": None}, "error_code": {"value": ["OOMKilled"], "items": []},
                           "first_seen": {"value": "02:13:58 UTC"}, "affected_users": {"value": 4200}}}

    async def decide(self, state, questions, **_):
        self._log("decide")
        return {"answers": {"severity": {"score": 3.0, "probabilities": {"3": 0.9}},
                            "team": {"choice": "payments", "probabilities": {"payments": 0.9}},
                            "page_human": {"noul": 0.95, "decision": True},
                            "customer_update": {"noul": 0.9, "decision": True}}}

    async def rerank(self, query, documents, **_):
        self._log("rerank")
        want = ("checkout-5xx", "generic-restart", "postgres-primary")
        res = [{"index": i, "action": "use" if d["id"].split("#")[0] in want else "skip",
                "relevance_score": 0.9 if d["id"].startswith("checkout") else 0.5}
               for i, d in enumerate(documents)]
        return {"results": res}

    async def injection(self, text, **_):
        self._log("injection")
        return {"injection": 0.01, "threshold": 0.5, "verdict": "benign"}

    async def compare(self, documents, **_):
        self._log("compare")
        ids = [d["id"] for d in documents]
        return {"pairs": [{"a": "generic-restart", "b": "postgres-primary", "related": 0.9,
                           "conflicts": [{"a": {"quote": "restart all pods"}, "b": {"quote": "Never restart"}}]}],
                "conflicts": [0] if {"generic-restart", "postgres-primary"} <= set(ids) else []}

    async def script(self, script, **_):
        self._log("script")
        risky = "--all" in script
        return {"verdict": "malicious" if risky else "benign", "malicious": 0.9 if risky else 0.02,
                "suspicious": 0.9 if risky else 0.03, "threshold": 0.5, "category": "x",
                "evidence": [{"start": 0, "end": 10}] if risky else []}

    async def fill(self, text, fields, **_):
        self._log("fill")
        return {"fields": {"title": {"value": "Checkout failing"}, "team": {"value": "payments"},
                           "severity": {"value": engine.SEV_LEVELS[3]}, "status_update": {"value": "We are on it."}}}

    async def grounding(self, answer, documents, **_):
        self._log("grounding")
        return {"verdict": "contradicted" if self.ungrounded else "grounded",
                "grounded": 0.3 if self.ungrounded else 0.95,
                "claims": [{"claim": answer, "label": "not_stated" if self.ungrounded else "supported"}],
                "unsupported_claims": [0] if self.ungrounded else []}


def incident():
    return json.loads((FIX / "sev1-checkout.json").read_text())


def gate(out, name):
    return next(g for g in out["gates"] if g["gate"].startswith(name))


def test_full_run_gates():
    out = asyncio.run(engine.triage(FakeClocked(), incident()))
    assert out["stages"]["understand"]["severity"] == "SEV1"
    assert out["stages"]["understand"]["team"] == "payments"
    assert gate(out, "no_injection")["passed"]
    # conflict: legacy runbook loses to nothing owned by payments -> lower relevance demoted
    cf = out["stages"]["retrieve"]["conflicts"][0]
    assert cf["demoted"] == "generic-restart" and cf["rule"] == "failed script inspection"
    assert out["stages"]["report"]["sources"][1]["id"] == "checkout-5xx"
    # destructive script is not runnable, safe ones are
    by_book = {s["runbook"]: s["runnable"] for s in out["stages"]["act"]}
    assert by_book["generic-restart"] is False and by_book["checkout-5xx"] is True
    assert out["stages"]["report"]["grounding"]["publishable"]
    assert {c["endpoint"] for c in out["calls"]} >= {"pipeline", "extract", "decide", "rerank",
                                                      "injection", "compare", "script", "fill", "grounding"}


def test_tainted_input_locks_and_pages():
    out = asyncio.run(engine.triage(FakeClocked(tainted=True), incident()))
    assert out["locked"] and out["stages"]["understand"]["page_human"]
    assert "[QUARANTINED]" in out["stages"]["airlock"]["clean"]


def test_ungrounded_update_blocks_publish(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB", tmp_path / "t.db")
    fake = FakeClocked(ungrounded=True)
    monkeypatch.setattr(main, "client", lambda: fake)
    tc = TestClient(main.app)
    out = tc.post("/api/triage", json=incident()).json()
    assert not out["stages"]["report"]["grounding"]["publishable"]
    r = tc.post("/api/publish", json={"incident_id": out["incident"]["id"], "update": "Fixed, no data lost."})
    assert r.status_code == 409
    fake.ungrounded = False
    r = tc.post("/api/publish", json={"incident_id": out["incident"]["id"], "update": "We are on it."})
    assert r.status_code == 200
    # raw text with personal data is never persisted
    import sqlite3
    stored = sqlite3.connect(tmp_path / "t.db").execute("SELECT record FROM incidents").fetchone()[0]
    assert "maria.lopez" not in stored
