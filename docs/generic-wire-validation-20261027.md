# Generic C engine validation, 2026-10-27

This is a bounded migration milestone on
`feature/description-driven-c-engine-20261027`. The online generic engine is C;
Python generates descriptions and controls offline checks/acceptance campaigns.
Three independent audit tasks covered wire rules, runtime sessions, and the
six profile descriptions. The root integration checked production CLI,
scheduler attribution, compatibility regressions and local network execution.

This is a historical execution record for the source hashes in its saved
report. Subsequent static review identified the nonzero-state selection
blocker, memory-novelty gate, UDP boundary mismatch and incomplete M3 semantic
checking documented in [current gaps](current-integration-gaps.md). The checks
below do not establish that these paths work. Later changes to offline checks,
report metadata and documentation have not been tested or built in this repair
pass; the historical pass results are not results for those changes.
The repair also changes generic statistics to version 2 and adds loader
example-ambiguity rejection. The saved unversioned report retains its original
v1 counter semantics; it is not retroactively rewritten as a new validation.

## Executed checks

| Check | Observed result |
| --- | --- |
| C wire ASan/UBSan harness | 207 assertions passed: forward `size_of`, referenced lengths with signed additions, resize/suffix preservation, bounds, atomic failure. |
| C six-profile ASan/UBSan harness | 14 fixture roundtrips and 982 assertions passed; no target exchange implied. |
| C generic runtime ASan/UBSan harness | 105 assertions passed: all sequence operations, M1-inclusive budgets, escaped diagnostics, shared response grammar, pending request handling. |
| C Modbus ASan/UBSan harness | 32 assertions passed: FC03 scalar projection, fragmented/coalesced TCP, wrong/duplicate/unsolicited response exclusion and session reset. |
| Generator and independent checker | Six files reproduce byte-for-byte; unsupported inventories contain 57 of the 71 original message IDs. |
| Production integration regression | `bash tests/protocol/run_all.sh /tmp/stateafl-generic-legacy-final` passed, including 19 CLI tests, 94 compiler tests, template/model regeneration, codecs, evidence and reproducible export tests. |
| Production C feedback harness | Generic preparation uses memory state ID 137; memory and coverage rewards affect that state's HEAD weight, while an unrelated state keeps uniform weights. AFL bitmap repeat and calibration exclusion passed. |
| Legacy randomized runtime ASan/UBSan | 84 loader cases, 250 random models, 25,000 random wire iterations and 100,096 checks passed; [source-bound report](../tests/protocol/evidence/runtime-results.json). |
| Final production build | `make -j2 afl-fuzz` passed. Two existing warnings remain: volatile source passed to memcpy, and unused `link_or_copy`. |

The first legacy regression exposed that regeneration/export did not include
the new generic files. Both workflows were fixed and the complete regression
was rerun successfully. A stale intermediate pending-response test expected
an unrelated response to release the request; the final implementation and
regressions retain it until the correct response or session reset.

## Actual online acceptance

The final source was built before this command:

```sh
python3 tests/generic-wire/run_live.py \
  --output /tmp/stateafl-generic-acceptance-final --seconds 12 --state-aware
```

The fictional UDP protocol was described in JSON and used no dedicated codec.
Its instrumented C target independently checked every received message. All
eight acceptance conditions passed. [The report](../tests/generic-wire/evidence/20261027/report.json)
records commands, source hashes and raw counters; accompanying wire and mutation
logs allow inspection of packet validity and feedback attribution.

| Observation | Value |
| --- | --- |
| Received packets passing independent target validation | 142 / 142 |
| Saved structured samples inspected | 100; contain visible HEAD, CONTENT and SEQUENCE edits |
| Mutation attempts / structured successes / rejections | 123 / 80 / 43 |
| HEAD / CONTENT / SEQUENCE successes | 41 / 20 / 19 |
| Raw mutation executions | 0 |
| Scheduler observations / rewards | 123 / 2 |
| New coverage tuples / new hit-count buckets | 2 / 20 |
| Queue discovery events / memory discovery events | 2 / 1 |
| Final state-0 layer weights | 16 / 17 / 16 |

Response counters are zero because this fixture declares a no-response
semantic transition. Actual response framing and correlation are exercised by
the separate generic runtime and Modbus TCP harnesses. StateAFL's inferred
memory states supplied the observed memory reward; it was not a description
state being counted as target feedback.

Every saved layer observation is attributed to state ID 0. A memory discovery
event does not prove that the fuzzer later selected that nonzero state and
reached generic mutation. The Modbus response harness calls APIs directly; it
does not establish socket-level compatibility with an industrial server.

The saved report hashes five source files, but not the executed fuzzer or target
binaries, complete build dependencies, toolchain or dynamic libraries. Its
committed evidence directory omits candidate replay files, binaries and build
logs; the wire log records validity and size rather than packet bytes. Counts
can be reconciled, but readers cannot independently re-inspect the reported
100 candidate contents from that directory. Reporting changes can describe
future artifacts accurately; they cannot fill these historical gaps.

## Remaining acceptance gaps

This validates integration, not industrial coverage gains. No comparison
campaign on the six industrial servers was executed for this grammar engine.
The six descriptions migrate 14 fixture messages; five remain offline-only,
and Modbus online scope is a one-register FC03 request/response. They do not
constitute complete protocol support. Arrays, conditional structures, bitfield
semantics, BER/UA encodings, broader cross-field/session bindings and service
coverage remain to be expressed with general grammar primitives and validated.
See [the profile inventory](generic-wire-profile-scope.md) for each protocol.

Each generic live session permits one outstanding request. Unrelated responses
preserve the pending request; a missing valid response requires a session reset.
Grammar-valid mutation guarantees only the constraints actually encoded in
that description. Coverage improvement needs repeated equal-budget experiments
on real target implementations after their description migrations are complete.
