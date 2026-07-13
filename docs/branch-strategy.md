
# Branch Strategy for `rpkv2`

## Branch roles

- `main`: stable, curated baseline
- `benchmark-2node-signed`: milestone integration branch for signed 2-node benchmark work
- `codex/*`: AI-generated task branches opened against the active milestone branch
- human clean branches: maintainer-authored salvage branches when AI output is stale/contaminated/wrong-base

## Principles

1. Prefer small, single-purpose branches.
2. Rebase or recreate quickly when milestone base moves significantly.
3. Never merge a Codex branch directly if it contains unexpected `src/`, `Cargo.toml`, or `Cargo.lock` changes for a docs/process scoped task.
4. Keep branch names explicit to intent:
   - `codex/<area>-<task>` for AI work
   - `human/<area>-<cleanup>` for human salvage/cleanup

## Recommended flow

1. Checkout `benchmark-2node-signed`.
2. Create `codex/<task>` branch.
3. Make minimal change set.
4. Run required checks (or document docs-only skip).
5. Open PR into `benchmark-2node-signed` with required metadata.
6. Squash/merge after review and verification.

## Anti-patterns

- Long-running AI branches accumulating unrelated changes.
- Mechanical formatting-only noise mixed with feature changes.
- Performance claims without benchmark artifacts.
- Positioning AF_XDP/DPDK as current path before baseline UDP is fully measured.

