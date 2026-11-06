# NightShift

**An on-call copilot where every step is gated.** An alert comes in at 2 a.m. NightShift masks personal data, catches instructions hidden in tickets and runbooks, works out severity and the owning team, picks the right runbook, inspects every remediation script before it can run, and writes a customer status update that **cannot be published until each claim in it is backed by evidence**.

Built on [Clocked](https://clocked.rezolve.ai): all nine endpoints plus `/pipeline`, and every result changes what the app does.

## The five stages

| # | Stage | Clocked | What the result changes |
|---|---|---|---|
| 1 | Airlock | `/pipeline` → `pii` (replace) + `injection` (`source: content`, `stop`) | Only masked text is stored or shared. Instruction-like text is cut out (`[QUARANTINED]`), the incident is **locked** to human sign-off, and a human is paged. |
| 2 | Understand | `/extract`, `/decide` (in parallel) | Facts come back with character offsets and are highlighted in the logs. `score` sets SEV1–SEV4, `choice` routes to a team, and `noul` decides paging and whether customers need an update. |
| 3 | Retrieve | `/rerank` → `/injection` per runbook → `/compare` | `use` / `expand` / `skip` picks runbooks. Tainted runbooks are dropped. Contradicting runbooks are detected. |
| 4 | Act | `/script` with the change policy as `instructions` | The Dry-run button is enabled only for benign scripts, and flagged lines are highlighted. The script verdict also **settles runbook conflicts**: the side that fails inspection is demoted. |
| 5 | Report | `/fill` → `/grounding` | `/fill` builds the incident record (generate, choice, score, yes_no). `/grounding` checks the status update claim by claim. Publish is blocked (HTTP 409) until unsupported claims are edited and re-verified. |

Conflict resolution order: failed `/script` inspection → not owned by the team `/decide` routed to → lower `/rerank` relevance.
If `/decide` and `/fill` disagree on the owning team, a "routing uncertain" gate is raised.

## Run it

```bash
cp .env.example .env            # add your Clocked API key
pip install -r requirements.txt
export $(cat .env | xargs)
python -m scripts.smoke         # one live call per endpoint, saves samples/
uvicorn app.main:app --reload   # http://localhost:8000
pytest -q                       # offline tests of the gating logic
```

Docker: `docker build -t nightshift . && docker run -p 8000:8000 --env-file .env nightshift`

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/triage` | Runs the five stages on `{alert, logs}` and returns stages, gates and the call log |
| POST | `/api/inspect` | Inspects any pasted script against the change policy |
| POST | `/api/verify` | Re-grounds an edited status update |
| POST | `/api/publish` | Server-side gate: re-verifies, returns 409 if ungrounded and 423 if locked |
| POST | `/api/unlock/{id}` | Human sign-off on a tainted incident |
| GET | `/api/incidents` | History (masked data only) |

## Design notes

- **Safety by construction:** raw text never touches disk. The publish gate runs on the server, so the UI button alone is not trusted.
- **Idempotency:** each logical call has one `Idempotency-Key` across retries (429/5xx with backoff). Concurrency is capped at 4.
- **Cost:** about 15 calls per incident. The call log shows the time and credits for each call.
- **Runbooks** are plain Markdown in `app/runbooks/`. Sections become rerank passages, and fenced code blocks become inspectable scripts.

All incident data in `app/fixtures/` is fictional.
