# Repeated BACnet control experiments

`tests/protocol/controlled_experiments.py` separates functional YAML assertions
from descriptive performance comparisons. It runs the local BACnet server over
loopback UDP with the existing integration harness transport settings. It never
overwrites an evidence directory or changes the source corpus/models: each run
uses a copied model package and a new output directory.

```sh
python3 tests/protocol/controlled_experiments.py \
  --output /tmp/bacnet-controlled-20261025 \
  --repeats 3 --seconds 15 --seed-base 20261025
python3 tests/protocol/test_experiment_analysis.py
```

Build `afl-fuzz` and the integration server first. Before creating output, the
driver checks that the actual fuzzer binary advertises `--random-seed` and
`--protocol-save-candidates`. The default server is
`../bacnet-stack/build-protocol-integration/server`; `--server` and `--spec-dir`
select other local builds/model packages.

## Performance comparison

The default experiment has 15 sequential runs: five modes, each repeated three
times. `--repeats` must be at least three. Every mode uses the same four normal
LE32 seeds (`Who-Is`, `ReadProperty Object_Name`, `Vendor_Name`, `Object_List`),
the same target, UDP timeouts, CPU/ASLR settings, and time budget after readiness.
Each run gets a fresh server/fuzzer/output directory. Ports are allocated from
loopback's ephemeral range and recorded.

| Mode | Mutation mode | Enabled layers |
| --- | --- | --- |
| `legacy` | existing AFL mutation | no protocol engine |
| `head` | `valid` | HEAD |
| `head_content` | `valid` | HEAD, CONTENT |
| `all` | `valid` | HEAD, CONTENT, SEQUENCE |
| `hybrid` | `hybrid` | HEAD, CONTENT, SEQUENCE |

Round 1 uses the table order, round 2 begins with `head`, round 3 begins with
`head_content`, and later rounds continue the cyclic rotation. Mode order
therefore changes with the repeat, although three rounds do not balance all five
positions. Use five or ten repeats for complete position balance. The uint32
random seed is `seed_base + repeat_index`, shared across modes in that round.
This controls StateAFL's internal RNG; different mutation engines consume draws
differently, and scheduling, network timing and target addresses can still vary.
It does not promise identical execution streams across independent processes.

`--performance-candidates 24` saves the same bounded number of actual post-ready
network sequences for every mode. Set it to zero to disable capture for a longer
timing study. Capture adds bounded file I/O; keep the setting identical across
modes. Candidate structure ratios describe the first captured sequences, not an
unbiased sample of the entire campaign. These sends must not be confused with
new coverage entries in the queue, which are selected by feedback.

Each run stores command/environment, random seed, a SHA-256 manifest of source
files, fuzzer binary, target, copied YAML/IR, and exact seed bytes. Source hashes
include current uncommitted source contents and the experiment driver itself.
The metadata records model hashes before and after the launch wrapper rebuilds
the IR. The source corpus remains unchanged.

Metrics include:

- Executions and execution rate with the calibration baseline subtracted. The
  driver prefers the synchronous `experiment_baseline.json` written before
  ready; `experiment_protocol_baseline.json` supplies the corresponding protocol
  counter baseline, including responses. If unavailable, it explicitly records the delay of the first complete
  stats snapshot after ready. Missing baselines yield `null`, never a fabricated
  zero. The fuzzer's cumulative `execs_per_sec` is retained as raw evidence but is
  not the comparison's execution rate.
- Actual `fuzz_bitmap` bytes unequal to `0xff`, plus cleared hit-class bits.
  The rounded `bitmap_cvg` text is retained only as supporting evidence. A
  byte represents a bitmap location and can alias multiple code edges; these
  counts are not a count of distinct source-level branches. When the synchronous
  baseline is present, coverage gain subtracts its virgin-map count.
- Memory state IDs, graph edges and state sequences from IPSM evidence, queue
  size/growth, and crashes/hangs. Semantic protocol states and memory-derived
  states have different meanings.
- Structured/raw execution shares, rejection share of structured attempts,
  response/correlated-response counters, and actual-send structural samples.
  Protocol counters unavailable in `legacy` remain `null`; actual-send samples
  still permit a bounded wire-structure comparison. Responses are parsed BACnet
  responses, not an assertion that every request succeeded semantically.

The result contains per-mode min, 25th percentile, median, 75th percentile and
max using linear interpolation, together with differences from `legacy` paired
by round. The minimum three runs support descriptive spread only. No p-value,
statistical-significance claim, or claim of a bug-finding benefit is generated.
Zero crashes/hangs means zero observed under this target, corpus, model and time
budget. Short runs cannot establish absence of bugs. A successful functional
control does not imply a performance benefit.

## Independent functional controls

The default driver also runs three short live controls, using only the normal
`ReadProperty Object_Name` seed and HEAD mutation. ReadProperty's control fixture
is copied from that actual unchanged seed (NPDU control 0); other messages keep
their fixture values. All NPDU control fields are fixed. In ReadProperty, Invoke ID is
the only mutable HEAD field, with one `enum` strategy and one allowed enum value.
The A and B models select Invoke ID 33 and 77 respectively. Both use the same
random seed and budget; the only policy difference is that enum value.

The assertions parse LE32 replay files saved by the fuzzer after actual network
sends and require the sidecar's `structured: true`. Mutation JSONL alone is not
accepted as wire evidence. Every captured A request must equal the normal seed
with only Invoke ID set to 33; every B request must equal it with only Invoke ID
set to 77. Framing, all other HEAD fields and CONTENT bytes must remain equal.
A missing candidate sample fails the functional control.

The third run uses the Invoke ID 33 model with `near_valid`. Each saved request
must equal the valid A wire except that BVLC's advertised length is exactly one
larger than the actual datagram. This tests repair followed by the single
intentional length violation. It does not treat a server rejection as a crash.

A fourth, negative control changes a dependency source to a nonexistent field.
The YAML launch wrapper must return an error naming the missing source before
any fuzzer/target starts. A target launcher would write a marker before execing
the real target; that marker must remain absent. The invalid model and rejection
log are retained for review.

Use `--controls-only` to run just these assertions, or `--skip-controls` to run
only the repeated comparison. `--control-seconds` and `--candidate-limit` set
the live functional budget and bounded save limit. The controls' metrics do not
enter the five-mode performance summaries.

## Evidence layout

`metadata.json` contains the schedule and initial manifests; `summary.json`
contains descriptive analysis and separate functional results. Each
`repeat-NN/MODE/` holds `command.json`, `fuzz.log`, `result.json`, the ready
snapshot, and the complete fuzzer output. `functional-controls/` retains both
YAML variants, the one-seed corpus, each live run and the negative dependency
fixture/log. A nonzero driver exit preserves all completed evidence and the
failed checks; it does not erase inconvenient runs.


For the final one-seed functional reproduction on this machine, use
`--controls-only --control-seconds 15 --startup-usecs 500000`.
An intermediate repetition with 200 ms startup failed calibration in two controls;
those logs are retained. The 500 ms functional rerun passed all wire assertions.
The completed 15-run performance table used 200 ms uniformly and is a separate comparison.
