"""Live check: one call per endpoint, prints the top-level keys of each response.
Run once with your key to confirm response shapes:  python -m scripts.smoke"""
import asyncio, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.clocked import Clocked

async def main():
    c = Clocked()
    t = "ALERT service=checkout-api at 02:14 UTC. HTTP 503 for 4,200 customers. Contact ana@example.com."
    calls = {
        "decide": dict(state=t, questions={"sev": {"type": "score", "criteria": ["low", "high"]}}),
        "extract": dict(text=t, fields={"service": {}, "affected_users": {"format": "integer"}}),
        "fill": dict(text=t, fields={"title": {"type": "generate", "max_tokens": 20},
                                     "urgent": {"type": "yes_no", "description": "Is it urgent?"}}),
        "pii": dict(text=t, anonymize="replace"),
        "injection": dict(text=t, source="content"),
        "script": dict(script="kubectl -n payments rollout status deploy/checkout-api"),
        "grounding": dict(answer="Checkout returned 503 errors.", documents=[t]),
        "compare": dict(documents=[{"id": "a", "text": t}, {"id": "b", "text": "Checkout is healthy."}]),
        "rerank": dict(query="why is checkout failing", documents=[t, "Holiday calendar."]),
        "pipeline": dict(text=t, steps=[{"pii": {}}, {"injection": {}, "stop": True}]),
    }
    for ep, body in calls.items():
        r = await c.call(ep, body)
        print(f"/{ep}: {list(r)}")
        os.makedirs("samples", exist_ok=True)
        json.dump(r, open(f"samples/{ep}.json", "w"), indent=2)
    print(json.dumps(c.reset_log(), indent=1))
    await c.close()

asyncio.run(main())
