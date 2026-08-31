---
description: Code quality and safety constraints
alwaysApply: true
---

# Code

- Before adding a helper, search for an existing one. Reuse or extend rather than adding a near-duplicate.
- Place new code with the feature it belongs to; import across features via their public entry point, not deep paths.
- Prefer the standard library or an already-present dependency over adding a new one; flag any new dependency in your report.
- Never add a dependency that is prerelease, unmaintained (archived, deprecated, or no release in roughly two years), or requires an EOL runtime. Flag existing ones; don't migrate them unasked.
- Validate input that crosses a trust boundary (user input, network, files, environment). Never log or commit secrets. Wrap errors with context; never swallow them.
