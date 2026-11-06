"""NightShift HTTP API + static UI.  Run: uvicorn app.main:app --reload"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import engine
from .clocked import Clocked, ClockedError

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
DB = Path(os.getenv("NIGHTSHIFT_DB", ROOT / "nightshift.db"))

app = FastAPI(title="NightShift", version="1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, created REAL, "
                "severity TEXT, team TEXT, locked INT, published INT DEFAULT 0, record TEXT)")
    return con


def client() -> Clocked:
    try:
        return Clocked()
    except RuntimeError as e:
        raise HTTPException(500, str(e))


class Incident(BaseModel):
    id: str | None = None
    title: str = "Ad-hoc incident"
    source: str = "manual"
    alert: str
    logs: str = ""


class ScriptIn(BaseModel):
    script: str


class VerifyIn(BaseModel):
    incident_id: str
    update: str


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/fixtures")
def fixtures():
    return [json.loads(p.read_text()) for p in sorted(FIXTURES.glob("*.json"))]


@app.get("/api/runbooks")
def runbooks():
    return [{k: b[k] for k in ("id", "title", "owner")} for b in engine.load_runbooks().values()]


@app.post("/api/triage")
async def triage(inc: Incident):
    inc.id = inc.id or f"INC-{int(time.time())}"
    c = client()
    try:
        out = await engine.triage(c, inc.model_dump())
    except ClockedError as e:
        raise HTTPException(502, str(e))
    finally:
        await c.close()
    u, rep = out["stages"]["understand"], out["stages"]["report"]
    # Only masked material is persisted: raw/clean text never touches disk.
    stored = {"masked": out["stages"]["airlock"]["masked"], "record": rep["record"],
              "sources": rep["sources"], "gates": out["gates"]}
    with db() as con:
        con.execute("REPLACE INTO incidents (id, created, severity, team, locked, record) VALUES (?,?,?,?,?,?)",
                    (inc.id, time.time(), u["severity"], u["team"], int(out["locked"]), json.dumps(stored)))
    return out


@app.post("/api/inspect")
async def inspect(body: ScriptIn):
    c = client()
    try:
        return await engine.inspect_script(c, body.script)
    finally:
        await c.close()


@app.post("/api/verify")
async def verify(body: VerifyIn):
    """Engineer edits the status update; it is re-checked before Publish unlocks."""
    with db() as con:
        row = con.execute("SELECT record FROM incidents WHERE id=?", (body.incident_id,)).fetchone()
    if not row:
        raise HTTPException(404, "unknown incident")
    c = client()
    try:
        return await engine.verify_update(c, body.update, json.loads(row[0])["sources"])
    finally:
        await c.close()


@app.post("/api/publish")
async def publish(body: VerifyIn):
    """Server-side gate: publishing re-verifies; the UI button alone is not trusted."""
    res = await verify(body)
    with db() as con:
        locked = con.execute("SELECT locked FROM incidents WHERE id=?", (body.incident_id,)).fetchone()[0]
    if not res["publishable"]:
        raise HTTPException(409, {"reason": "ungrounded claims", "unsupported": res["unsupported"]})
    if locked:
        raise HTTPException(423, "incident locked: tainted input needs human sign-off first")
    with db() as con:
        con.execute("UPDATE incidents SET published=1 WHERE id=?", (body.incident_id,))
    return {"published": True, "update": body.update}


@app.post("/api/unlock/{incident_id}")
def unlock(incident_id: str):
    with db() as con:
        con.execute("UPDATE incidents SET locked=0 WHERE id=?", (incident_id,))
    return {"unlocked": incident_id}


@app.get("/api/incidents")
def incidents():
    with db() as con:
        rows = con.execute("SELECT id, created, severity, team, locked, published FROM incidents "
                           "ORDER BY created DESC LIMIT 50").fetchall()
    return [dict(zip(("id", "created", "severity", "team", "locked", "published"), r)) for r in rows]
