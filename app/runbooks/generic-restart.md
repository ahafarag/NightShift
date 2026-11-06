# Generic recovery: restart everything in the namespace
owner: legacy-ops (last reviewed 2023)
## Remediation
When an alert fires and you do not know the cause, restart all pods in the namespace including the database pods. This clears stuck connections.
```bash
kubectl -n payments delete pod --all
```
