# Native passive inspection checks

`test_native_inspection.c` calls the real `native_json`, `native_layout`,
`native_observation` and shared `native_inspection_dispatch` APIs. All fixtures
are fictional short layouts and producer-declared local observation records.
The test program creates its own private temporary directory with `mkdtemp`,
uses `tmpfile` for output, and removes fixture files on normal exit or a failed
check. It does not start a target, create sockets, generate mutations, or send
protocol traffic. Checks use an explicit failure macro and remain enabled with
`NDEBUG`.

**Status for this change: source reviewed only. No compiler, test binary,
sanitizer, example or target has been run. There are no runtime pass results.**

From the StateAFL repository root, the opt-in build commands are:

```sh
make native-inspection-tests
make native-inspection-tests-sanitized
```

These commands only build the ordinary and AddressSanitizer/UndefinedBehaviorSanitizer
test binaries. The corresponding opt-in execution commands, for a later test
session, are:

```sh
make check-native-inspection
make check-native-inspection-sanitized
```

Neither build nor execution target is invoked by the default `all` target. The
test source needs a POSIX environment for `mkdtemp`, `unlink` and `rmdir`. On a
compiler without `__int128`, it checks the documented layout rejection and
skips the layout semantic cases; JSON, observation and dispatch checks remain.

| Test function | Intended checks, not yet executed |
| --- | --- |
| `test_json_values` | Unsigned/signed boundary integers; rejected typed conversions leave outputs unchanged; embedded NUL is length-aware and cannot alias a required key; parser owns a source copy. |
| `test_json_rejections` | Duplicate decoded keys, malformed UTF-8/surrogates/escapes, unsupported numeric forms, trailing input, missing API arguments, excessive nesting, byte and node limits. |
| `test_json_output_and_files` | Explicit-length string escaping, preserved raw value slices, Unicode surrogate-pair decoding, zero-byte file limit and failure output reset. |
| `test_layout` | Fixed and enumerated scalars (`values`), lengths from prior fields, little-endian bit carriers, local reference shadowing, transparent choice/bounded references, truncation versus invalid complete bounded content, trailing bytes, invalid descriptions/expressions and decoded-field limits. |
| `test_observation_history` | Empty input, aligned producer records, timeout/partial/unmatched events clear current candidates while preserving historical confirmation. |
| `test_observation_prediction_and_pairing` | Prediction never becomes confirmation; ambiguous candidates remain one grouped row; missing pair/synchronization, unaligned markers and zero/synthetic memory labels do not create aligned relations. |
| `test_observation_identity` | Fresh confirmed reset isolates history and permits model changes; identical marker names in different sessions/epochs stay in separate partitions. |
| `test_observation_rejections` | Missing start, duplicate marker, stale epoch, repeated start/reset, unconfirmed reset, changing model, nonincreasing index, invalid candidate/evidence structure, oversized memory label and event count, unknown properties. |
| `test_diagnostic_and_required_arguments` | Diagnostic bounds and sentinel preservation, NULL formatter arguments, required API arguments, caller-owned output streams. |
| `test_dispatcher` | Shared dispatch result codes `-1/0/1/2`, successful passive inspection, missing files, NULL/invalid argument vectors, unknown selectors and rejected fuzzer/target argument mixing. |

The tests exercise passive modules and the same dispatch function called at the
start of `afl-fuzz`. Calling that function directly does **not** constitute a
complete fuzzer execution, mutation, network, coverage, queue or scheduling
regression. This suite also does not verify the five existing protocol YAML
descriptions, Python/YAML interpretation, producer truthfulness, real memory
snapshot synchronization, or protocol-state inference.

Resource failure branches are reviewed in source but this suite does not inject
allocation failure, interrupted file reads, output-write/flush failure or
process termination. Sanitizer and leak checks remain pending until their
execution is explicitly performed. Passing these tests later would validate
their stated cases, not establish general memory safety or paper-method
effectiveness.
