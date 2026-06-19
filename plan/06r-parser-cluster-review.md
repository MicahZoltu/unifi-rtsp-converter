# Step 06r — Quality Review: Parser Cluster

**Depends on:** Step 06 (parser cluster complete: 00–06).
**Type:** Dedicated quality review — adds no features.

## Goal

Step back and evaluate the **overall** quality of the parser cluster as a
hostile reviewer, before the codebase grows the RTSP/RTP/SDP layer on top of
it. Pay down any debt now, while it's cheap. This is where we catch the
"each piece tested fine in isolation but the whole is a mess" problems.

## Review procedure

Read **every** module in the cluster end to end: `flv_parser.rs`, `avc.rs`,
`amf.rs`, plus `logging.rs`/`config.rs` (touched early) if they interact.
Also re-read `PROJECT.md` §"The Stream Format" and §"Implementation
Specification" items 3–6 against the implementation.

Check, concretely:

1. **Cross-module consistency.**
   - Are error types shaped consistently (`ParseError`, `AvcError`, …)? Or did
     each module invent a different convention? If divergent, unify now.
   - Is the `NaluFrame` / `Frame` / `VideoTagEvent` vocabulary consistent, or
     are there overlapping types that should collapse into one?
   - Do all parsers return `Result<_, E>` with the same truncation/EOF story?
2. **Abstraction boundaries.** Does `flv_parser` own byte framing while `avc`
   owns codec decoding — or has logic leaked across the seam (e.g. `flv_parser`
   reaching into AVC details, or `avc` knowing about FLV tag headers)? Fix any
   leak by moving code to the correct module.
3. **Module layout vs `PROJECT.md`.** Does the actual file structure still
   match the spec's "File Structure" section? If a module was born that isn't
   in the spec (e.g. `amf.rs`), confirm it's the right call and note it.
4. **Naming.** Re-read every public item. Any name that only makes sense to
   the author who wrote it → rename. Constants for every magic byte.
5. **Error handling.** Every `Result` is propagated or logged; no `unwrap` in
   non-test code; error variants are exhaustive and used.
6. **Tests.** Are tests readable, named for what they assert, and asserting
   exact values? Any test that's actually testing integration disguised as a
   unit test → split or move. Any logic with no test → add one.
7. **Dead code / duplication.** Remove unused items. Factor duplicated byte-
   reading helpers (BE u24, BE u32, SI24, length-prefixed NALUs) into a shared
   spot if they appear in >1 module.
8. **Documentation.** Every public item has `///` explaining intent.
9. **Run the full gate:** `cargo build` (no warnings), `cargo test` (green),
   `cargo clippy -- -D warnings` on the cluster.

## Reconcile `DEBT.md`

- Resolve every `FIX NOW` item logged by steps 00–06 (delete the line).
- For each `TRIGGER:` item, confirm the trigger is still concrete and
  relevant; rewrite or remove as needed.
- If new debt was found during this review, either fix it now (preferred) or
  log it with the appropriate tag.
- State the outcome explicitly: "DEBT.md empty: confirmed" or list what
  remains and why.

## Validation (review pass — no new automated tests required)

This step "passes" when, and only when:

- The Standard Quality Gate is green across the whole cluster.
- The reviewer can articulate, for each module, a one-sentence description of
  its responsibility that matches its actual contents — no leaks, no orphans.
- `DEBT.md` is reconciled (empty or fully re-justified).
- A clean `cargo test` from `cargo clean` passes.

If the review surfaces real issues, **do not proceed to step 07.** Loop back to
the offending step(s) (00–06), fix them, and re-run this review. Iterating now
is far cheaper than carrying parser debt into the RTP/RTSP layers.

## Do not

- Do not add features (no RTSP, no RTP, no stream state). This step is review
  and cleanup only.
- Do not "tidy" by rewriting working code for style preference alone — changes
  must address a concrete smell or debt item. Avoid churn.
