# Checkout API 5xx spike
owner: payments-team
## Symptoms
Checkout API returns HTTP 502/503 to customers. Error budget burns fast. Payment confirmations stop arriving.
## Diagnosis
Check the checkout-api pods for OOMKilled restarts and the upstream payment-gateway latency. If the pods restart with OOMKilled, the memory limit is too low for the current traffic.
## Remediation
Scale the checkout-api deployment out and raise the memory limit to 1Gi. Restart pods one at a time with a rolling restart; do not delete the deployment.
```bash
kubectl -n payments scale deploy/checkout-api --replicas=8
kubectl -n payments set resources deploy/checkout-api --limits=memory=1Gi
kubectl -n payments rollout restart deploy/checkout-api
kubectl -n payments rollout status deploy/checkout-api --timeout=300s
```
## Communication
Customer-facing update within 15 minutes for any SEV1. State impact, start time and next update time. Do not promise a root cause before it is confirmed.
