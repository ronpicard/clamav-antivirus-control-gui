# About these rules

This document describes how the pack is organized and what each rule file does.

## How rules work

Cursor **project rules** are Markdown files with optional YAML **frontmatter**, stored under **`.cursor/rules/`**. In this repository they live in **`.cursor/rules/ai-rules/`**, grouped into five subfolders. Each file is `.mdc`, supporting `description`, `globs`, and `alwaysApply` in its frontmatter. Cursor decides which rules to include based on that metadata: `alwaysApply: true` rules are candidates for every conversation; others apply when **file paths match `globs`** (e.g. only while editing `*.md`) or when you **@-mention** a rule. Rule files toggle on / off by renaming between `<name>.mdc` and `<name>.mdc.disabled`—the AI Rulebook extension does this for you. Rules are versioned with the repo like normal docs.

## Layout

```text
.cursor/rules/ai-rules/
├── ABOUT_RULES.md
├── coding-rules/            # how to write and ship code
├── documentation-rules/     # how to maintain docs and changelogs
├── role-rules/              # how to frame replies for a given audience
├── rules-for-rules/         # how the rule pack itself is authored and announced
└── test-rules/              # how to design and write tests
```

## Modes (provided by the AI Rulebook extension)

Four commands flip curated presets via the same enable / disable mechanism:

| Command | Effect |
|---------|--------|
| **AI Rulebook: Mode — Plan** | Enables `role-architect`; disables every other role and every test rule. Coding / docs rules left alone. |
| **AI Rulebook: Mode — Build** | Enables `role-developer`; disables every other role and every test rule. |
| **AI Rulebook: Mode — Test** | Enables `role-tester` and **all** `test-rules/*`; disables every other role. |
| **AI Rulebook: Mode — Role…** | QuickPick to enable a single role; disables the other roles. Doesn't touch test rules. |

Modes never disable the always-on coding / documentation / meta rules—those stay on across modes.

## Rule reference

### `coding-rules/`

| Rule | When it runs | Summary |
|------|--------------|---------|
| `write-clean-code.mdc` | Always (`alwaysApply: true`). | Naming, function size, comments, explicit dependencies, clear errors. |
| `reuse-code-before-duplicating.mdc` | Always. | Search for existing helpers before adding new ones; extract on the third copy. |
| `organize-repository-by-feature.mdc` | Always. | Feature-first folders, tidy root, stable entry points, colocated tests. |
| `secure-code-data-and-dependencies.mdc` | Always. | Secrets, input handling, authorization, crypto, dependencies, logging defaults. |
| `prefer-lts-stable-runtimes-and-libraries.mdc` | Always. | LTS or current stable releases, sensible pinning, security patches. |
| `verify-syntax-and-fix-before-finishing.mdc` | Always. | Re-checks touched files for syntax / type issues and fixes what's safe. |
| `remove-dead-code-and-unused-files.mdc` | Always. | Looks for unused code and orphan files; removes only when clearly safe. |

### `documentation-rules/`

| Rule | When it runs | Summary |
|------|--------------|---------|
| `update-changelog-for-notable-changes.mdc` | Always. | Keep `CHANGELOG.md` current for user-visible changes (Keep a Changelog style). |
| `append-and-deduplicate-requirements.mdc` | Always. | Capture stated requirements in `REQUIREMENTS.md`, merge near-duplicates. |
| `use-this-format-for-markdown-files.mdc` | Glob-only: `**/*.{md,mdx}`. Also when **@-mentioned**. | Standardizes Markdown structure, lists, code samples, links, README sections. |

### `role-rules/` (off by default; toggled by mode commands)

| Rule | Audience framing |
|------|-----------------|
| `role-developer.mdc` | Working software developer—skip basics, lead with code and trade-offs. |
| `role-architect.mdc` | Lead with constraints, boundaries, and 2–3 viable approaches. |
| `role-tester.mdc` | Lead with what to verify, expected vs. actual, and risk. |
| `role-cyber-expert.mdc` | Treat everything as threat surface; STRIDE / OWASP framing. |
| `role-product-manager.mdc` | Lead with user value, scope, sequencing, rollout risk. |
| `role-beginner.mdc` | Define jargon; full commands; one safe path; explain *why*. |
| `role-expert.mdc` | Skip foundations; surface non-obvious edge cases; primary sources. |
| `role-end-user.mdc` | No code or jargon; what the user sees, clicks, and gets. |

### `rules-for-rules/`

| Rule | When it runs | Summary |
|------|--------------|---------|
| `state-active-project-rules-in-prompt-response.mdc` | Always. | First substantive reply prints a verbatim **`### Active project rules`** bullet list of every active rule path. |
| `evolve-rules-when-codebase-patterns-change.mdc` | Always (when not `.mdc.disabled`). | Triggers new / updated rules when patterns stabilize across the codebase. |
| `write-cursor-rules-for-this-project.mdc` | Glob-only when paths match `**/.cursor/rules/ai-rules/**/*.mdc`. Also @-mention. | Where `.mdc` files go, frontmatter, naming, body format, quality bar, and ongoing maintenance / deprecation. |

### `test-rules/` (off by default; enabled by Mode — Test)

| Rule | Test type |
|------|-----------|
| `write-unit-tests.mdc` | Pure-logic units; AAA layout; deterministic, fast. |
| `write-smoke-tests.mdc` | Critical happy paths only; fail-fast; block builds. |
| `write-regression-tests.mdc` | One test per fixed bug; reference issue / PR. |
| `write-integration-tests.mdc` | Real boundaries (DB, HTTP, queue); ephemeral environments. |
| `write-end-to-end-tests.mdc` | Top user journeys; stable selectors; flakes are bugs. |

For VS Code UI settings bundled with this workspace, see **`.vscode/settings.json`** at the repo root (that file is not a Cursor rule).

## Extension vs repo (AI Rulebook VSIX)

The **AI Rulebook** extension ships a copy under **`bundled/ai-rules/`** with the same subfolder layout. The **source of truth** is **`.cursor/rules/ai-rules/`**. After editing rules, run `npm run sync-bundled` (and `npm run verify:bundled` to confirm they match) before packaging the extension.
