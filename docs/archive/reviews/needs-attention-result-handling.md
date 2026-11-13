# Needs attention result handling

Scan evidence collection failures are displayed as **Needs attention** in CLI and Console. Existing wire status `error`/`UNKNOWN`, classification and CLI exit code 3 remain compatible.

Console keeps the observation and marks the requirement `needs_attention` with no current conformance result. It does not approve the requirement, create a security finding, or resolve an existing genuine finding. The last verified timestamp/revision remains historical. A later PASS or FAIL establishes a new result.

Assessment controls display the collection cause and action. Historical finding titles beginning `Execution error:` render as `Needs attention:`; stored historical findings are not migrated or deleted.

Current catalog eligibility prevents human requirements in old automated snapshots from being queued or applied as automated conclusions. Explicit selections and stale queued manifests return actionable guidance.

Validation: Console Agent suite 36 tests / 247 assertions; CLI presentation 12 assertions and diagnostics 196 assertions across 44 autonomous requirements. Broader Console suite initially had six failures: the deployment-revision expectation was updated and now passes; five unrelated UI/route expectations remain unresolved. QA PHAR rebuilt at artifacts/magebean-internal-qa.phar. No production deployment performed.
