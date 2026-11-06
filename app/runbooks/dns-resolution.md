# Internal DNS resolution failures
owner: network-team
## Symptoms
Services log "no such host" or SERVFAIL for internal names. Errors appear across many unrelated services at once.
## Remediation
Restart CoreDNS with a rolling restart and verify the upstream resolvers respond.
```bash
kubectl -n kube-system rollout restart deploy/coredns
kubectl -n kube-system rollout status deploy/coredns
```
