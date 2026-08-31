
# Docs

If the project has no existing documentation convention, use this layout;
if it already follows a different one, match it instead:

- The repo root is for files platforms and tools read by path: `README.md`,
  `CHANGELOG.md`, `AGENTS.md`, `LICENSE`, `CONTRIBUTING.md`, and
  `SECURITY.md`.
- Feature specs follow GitHub Spec Kit: `specs/<NNN-feature>/spec.md` with
  its `plan.md` and `tasks.md`, and project principles in
  `.specify/memory/constitution.md`.
- Every other doc lives under `docs/` and is linked from `README.md`.
- Place a doc not listed below by the same principle: root only if a
  platform reads it there, otherwise `docs/`.

Before reporting a task done, scan this trigger list once against what you
changed. Update only when the file already exists and the trigger applies:

- `README.md` — usage or configuration changed.
- `CHANGELOG.md` — release-worthy change, under `[Unreleased]` in Keep a
  Changelog form (`Added`/`Changed`/`Fixed`). Entries are user-facing:
  describe the visible change, not the implementation; skip internal
  refactors.
- `AGENTS.md` — build or test commands, conventions, or other
  agent-relevant facts changed.
- `CONTRIBUTING.md` — contribution process, dev setup, or how tests are
  run changed.
- `specs/<NNN-feature>/spec.md` — that feature's testable behavior
  changed; keep its `plan.md` and `tasks.md` consistent. (A project that
  tracks requirements in a single `docs/REQUIREMENTS.md` instead: same
  trigger.)
- `docs/ARCHITECTURE.md` — module boundaries, data flow, or a stated
  invariant changed.
- `docs/RELEASING.md` — the release process changed.
- `docs/DEPLOY.md` — deploy steps, environment variables, or infra config
  changed.
- `docs/decisions/` — you and the user chose between real alternatives and
  the choice constrains future work: append the next `NNNN-short-title.md`;
  never rewrite old ones.

Create a doc only on its trigger, never speculatively:

- Graduation: a `README.md` section has outgrown roughly a screenful
  (~50 lines) — move it to the matching file above and leave a link behind.
- First occurrence: `CHANGELOG.md` at the first release, `AGENTS.md` at
  the first agent-relevant fact worth recording, and
  `docs/decisions/0001-short-title.md` at the first recorded decision —
  confirm with the user before starting a project's first decision record.
- `specs/` only when the project already uses Spec Kit or the user asks to
  adopt it — never to document a feature you built without being asked for
  a spec.
