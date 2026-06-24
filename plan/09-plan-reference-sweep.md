# 09 — Sweep `plan/…` references

## Goal

Remove every dangling reference to the deleted `plan/` directory from `src/` doc comments, string literals, and the surviving `.md` files (`PROJECT.md`, `AGENTS.md`, `flvproxy.ini.example`). Each citation is either deleted (if it only pointed at a now-gone file) or replaced with an inline spec note (RFC section, behaviour summary, or the constant's rationale) so the comment still carries the *why* without depending on an external file.

## Context

The old `plan/` directory was deleted after the build plan was completed. `AGENTS.md`'s History section confirms the project deliberately moved away from plan-step references. But `src/` is full of `///` comments citing `plan/README.md`, `plan/26-…`, `plan/28`, `step 16`, `step 21`, `step 25b`, etc. — pointers to a folder that no longer exists. These are broken references that violate the AGENTS.md "no dangling `see DEBT.md`/`plan/…`" spirit now that both `DEBT.md` and `plan/` are gone. Doing this sweep *after* steps 01–08 avoids re-touching comments those steps already updated.

## Scope

In: every `plan/…`, `step NN`, `plan/NN-…`, `plan/README.md`, `DEBT.md` reference in `src/**/*.rs`, `PROJECT.md`, `AGENTS.md`, `flvproxy.ini.example`.

Out: any logic change. This step is pure comment/prose editing. `rustfmt` is not affected (comments are not reformatted), but the build/clippy/test must still pass to confirm no accidental code change.

## Approach

1. Enumerate every reference. Run (via Grep tool, not bash grep): patterns `plan/`, `step \d`, `DEBT\.md`, `DEBT\.md`-style `step \d+` mentions, `plan/README`, `redalert`, and historical step numbers in doc prose. Capture the file:line for each.
2. For each reference, decide per the AGENTS.md comment policy:
   - If the citation is the *only* content of a comment that restates the obvious ("Per `plan/26` task 1" prefix on a comment that otherwise explains the code), delete the citation prefix and keep the substantive explanation, or delete the whole comment if nothing of value remains.
   - If the citation carries a spec reference that the code needs (e.g. "per RFC 6184 §8.1", "per WS-Discovery §3.4"), keep the spec reference and delete the `plan/…` breadcrumb.
   - If the citation points at a plan step that justified a non-obvious choice (e.g. the `heartbeatsTimeoutMs: 60000` ground-truth note in `protect_controller.rs`), rewrite to state the ground truth inline ("Step-25b ground truth" → "Confirmed against the Protect 7.1.77 Node.js source") without the plan-step number.
   - Replace `see DEBT.md` / `tracked in DEBT.md` with the actual rationale inline, or delete if the rationale is now self-evident from the code. (Most `DEBT.md` references should already be gone after steps 01–06; this step catches stragglers.)
3. Special files:
   - `PROJECT.md`: rewrite any "see `plan/README.md`" pointers as inline statements. `PROJECT.md` is the user-facing overview; it should not cite an internal plan folder.
   - `AGENTS.md`: its History section explicitly mentions the plan/DEBT cleanup passes — update the History to note `plan/` and `DEBT.md` are both now removed and that step-number citations in source were swept. Keep the History accurate; do not pretend the passes never happened.
   - `flvproxy.ini.example`: remove any `plan/…` references in comments; the cert comment was already updated by step 05.
4. Do **not** introduce new `TODO`/`FIXME` markers. If a swept comment would otherwise become a "this is not yet done" note, delete it — there is no longer a ledger to track it, and the work is either done (steps 01–08) or intentionally out of scope.
5. Respect the one-paragraph-per-line wrapping rule throughout: rejoined prose onto single lines, preserve genuine structural newlines (list items, headings, byte-layout diagrams). This is the same mechanical rejoin the AGENTS.md History describes, applied to the new edits.

## Verification

- After the sweep, a final Grep for `plan/`, `step \d`, `DEBT\.md` across `src/`, `PROJECT.md`, `AGENTS.md`, `flvproxy.ini.example` should return zero matches (except legitimate uses — e.g. `AGENTS.md` History mentioning the cleanup itself, or `plan/README.md` cited *as the thing that was deleted* in a historical note, which is fine if phrased as history rather than a live pointer).
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo build --target x86_64-pc-windows-gnu` all green — confirms the sweep was comment-only.

## Files

- Every `.rs` under `src/` containing a `plan/`/`step N`/`DEBT.md` reference (expected: most files).
- `PROJECT.md`, `AGENTS.md`, `flvproxy.ini.example`.

## Acceptance

- No live `plan/…` or `DEBT.md` pointer remains in `src/` or the user-facing `.md` files; historical mentions in `AGENTS.md` History are acceptable only where clearly framed as past events.
- Every retained comment still explains *why* (spec citation, ground-truth origin, hazard, invariant) — none merely restates *what* or dangles a dead reference.
- Build/clippy/test/cross-compile green; no logic changed (confirm via `git diff --stat` showing only the expected files and `git diff` showing comment-only hunks).

## Notes

- This is the largest single step by file count but the lowest risk — it is mechanical prose editing. Budget a full session for the enumeration + edits + verification pass.
- Do this step last among the code steps so it sweeps the comments steps 01–06 already touched, avoiding double-edit churn.
