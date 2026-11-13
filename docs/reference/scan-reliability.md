# Scan budgets and durable agent delivery

## Deadline and lease checkpoints

`ScanDeadline` uses monotonic `hrtime` and a positive finite duration. Execution is
unlimited by default. Callers can pass a deadline through `ScanService`, `ScanRunner`
or `AgentScanner`. Agent configuration optionally accepts `scan_timeout_seconds`;
the budget starts after the manifest is retrieved, before planning/scanning. No CLI
option, default timeout, rule definition or payload schema is changed.

Checks not started before expiry produce typed UNKNOWN observations with internal
reason `SCAN_DEADLINE_EXCEEDED`. Collector checkpoints can interrupt enumeration
and reads via `ScanDeadlineExceeded`; runner catches only that exception, never
ordinary check failures. A deadline cannot appear as an unreadable file silently
skipped by source checks. Confirmed ALL failures stay FAIL. ANY with no passing
alternative and a deadline-skipped alternative is UNKNOWN. Existing no-deadline
all/any behavior remains frozen in the compatibility baseline.

HTTP collector caps request timeout to the remaining budget. HTTP is still fresh,
and a request prevented by expiry does not increment transport-attempt counters.
The stream fallback retains its existing whole-second timeout granularity. Runner
and collector checkpoints also invoke the agent's lease renewal callback; renewal
still happens only when 30 seconds have elapsed. Callbacks and cached data are
released when the collection session ends.

This is cooperative cancellation, not a hard process-wide wall-clock cap. A file
read, executable PHP configuration, subprocess, database call, Magento's separate
HTTP implementation or legacy Composer/API call can finish beyond the budget until
control returns to a supported checkpoint. Check-level HTTP timeouts still apply.
Lease renewal likewise cannot execute while synchronous legacy I/O is blocking.
The result of a check that completed normally is retained; later checks are skipped.

## Pending outbox protocol

`PendingOutbox` uses the existing queue location and original entry/payload fields.
Internal `_delivery.stage` is local metadata and is never sent as scan payload.

1. `queued`: atomically persisted result, unchanged scan UUID/idempotency key.
2. `uploaded`: server acknowledged scan upload; persist this stage before completion.
3. `completed`: server acknowledged job completion; persist before local bookkeeping
   and deletion. A restart can retry local state updates/cleanup without network I/O.

Entries without `_delivery` follow the legacy queued path. Each delivery step has
at most one network attempt per tick; next tick retries pending work before heartbeat
or job claim. Uploaded entries retry only completion. A lost upload acknowledgement
replays the same UUID/payload/key. Delivery errors after enqueue no longer mark the
job failed; errors before enqueue preserve the existing fail-job behavior. Completed
recovery updates `last_job_id` and `last_scan_uuid`, including after process restart.

Atomic JSON writes handle partial writes, flush and `fsync` when available before
renaming, with private temp/target permissions and cleanup on failure. This protects
against ordinary interrupted writes. Directory-entry synchronization and filesystem
guarantees differ by platform; complete power-loss durability is not promised.

`ConsoleTransport` separates orchestration from HTTP for fault-injection tests.
`ConsoleRequestException` preserves existing RuntimeException messages and adds
HTTP status/retryability. Transport errors, ambiguous successful acknowledgements,
408/425/429 and 5xx are retryable classifications. No automatic retry is added to
claim/start/update or other non-idempotent requests.

## Recovery boundaries

Delivery is at least once across crash windows. Exactly-once scan creation depends
on the server honoring the existing Idempotency-Key; replayed completion depends
on the server accepting repeated completion for the same job/UUID. Existing stored
lease tokens are preserved. Expired/rejected leases, authentication failures or other
permanent rejections require server/operator resolution; pending data is retained.

Corrupt/unsupported pending records surface an error and block new claims, preserving
existing fail-closed behavior. This phase does not invent a server lease-refresh
protocol, silently discard results, quarantine records or implement an unbounded
network retry loop.

## Validation

Run `php tests/run.php`. Added deterministic deadline tests, collector interruption
tests and outbox fault/restart tests cover lost acknowledgements, completion failure,
legacy pending records, corrupt stages, local state failures, lock release and normal
tick behavior. Loopback HTTP tests exercise real timeout clamping, cURL/stream
transport and error classification. Frozen compatibility baseline remains unchanged.
