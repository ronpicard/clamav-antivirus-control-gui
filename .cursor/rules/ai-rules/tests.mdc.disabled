---
description: Test and verification constraints
alwaysApply: true
---

# Tests

- For behavior changes, write the failing tests for the requirement first, then write the code to make them pass.
- Match the project's existing test file location and naming convention (colocated, mirrored `tests/` folder, feature-grouped, etc.). If none exists, ask when the user is available; working autonomously, default to colocating the test next to the source file it covers using the ecosystem's standard suffix (e.g. `foo.test.ts`, `foo_test.go`).
- Behavior changes require added or updated unit tests, then run the project's test command.
- Run the project's existing lint and type checks before reporting done; fix what you introduced. Never add, configure, or disable a linter the project doesn't already use.
- Never make a test pass by weakening an assertion, skipping or deleting the test, widening a type, or suppressing a lint rule.
- Report every failing test and every relevant check not run. Never describe an unrun test as passing.
