# Repository workflow

These instructions record the user's version-control preferences for this checkout.

- Continue on the existing branch `feature/protocol-aware-integration-20261025`.
  Do not create or switch branches unless the user changes this instruction.
- Its upstream is `origin/feature/protocol-aware-integration-20261025`.
  Keep feature work and its documentation in this repository.
- After each independently reviewable feature change, commit the relevant files
  and push to this same remote branch. Do not leave completed feature work only
  in the working tree. The user has authorized this commit-and-push workflow.
- Review the exact staged diff; exclude unrelated changes, generated results and
  credentials. Fetch the upstream before delivery and preserve remote changes.
  Use ordinary pushes, not force pushes.
- Verify the remote branch tip after pushing and report the commit and any sync
  failure accurately. A stale local tracking reference is not remote confirmation.
- The current user instruction is to defer tests. Perform static review and
  formatting checks without running tests, builds, examples or target services.
  A later user instruction may change this validation scope.

The offline tools have their own documented scope. Version-control delivery does
not establish runtime validation or change their integration status.
