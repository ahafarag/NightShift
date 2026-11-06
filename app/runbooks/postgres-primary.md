# Postgres primary under pressure
owner: data-platform
## Symptoms
Connection pool exhaustion, replication lag above 30 seconds, ORA-style or PG errors "remaining connection slots are reserved".
## Remediation
Never restart the primary database pod during business hours. Promote the healthy replica with the failover tool instead, after confirming replication lag is under 5 seconds.
```bash
patronictl -c /etc/patroni.yml list
patronictl -c /etc/patroni.yml failover --candidate pg-replica-1 --force
```
## Communication
Inform the payments team before failover; checkout writes pause for about 20 seconds.
