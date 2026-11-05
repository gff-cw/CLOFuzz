# Repository workflow

These instructions record the user's version-control preferences for this checkout.

- Continue on the existing branch `feature/description-driven-c-engine-20261027`.
  Do not create or switch branches unless the user changes this instruction.
- Its upstream is `origin/feature/description-driven-c-engine-20261027`.
  Keep feature work and its documentation in this repository.
- After each independently reviewable feature change, commit the relevant files
  and push to this same remote branch. Do not leave completed feature work only
  in the working tree. The user has authorized this commit-and-push workflow.
- Review the exact staged diff; exclude unrelated changes, generated results and
  credentials. Fetch the upstream before delivery and preserve remote changes.
  Use ordinary pushes, not force pushes.
- Verify the remote branch tip after pushing and report the commit and any sync
  failure accurately. A stale local tracking reference is not remote confirmation.
- The user authorizes compiling StateAFL and its components, executing local
  regression suites, and running controlled loopback test services to validate
  the executor extensions. This supersedes the earlier compile-only limit.
  Keep generated test output separate from committed historical evidence and
  describe actual runtime results and remaining limitations accurately.

The offline tools have their own documented scope. Version-control delivery does
not establish runtime validation or change their integration status.
