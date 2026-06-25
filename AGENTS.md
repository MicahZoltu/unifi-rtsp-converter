# AGENTS.md — contributor guide for agents and humans

This is the repository-wide contributor doc for code-quality conventions that apply to *every* change, regardless of which build-plan step it belongs to. The build plan lives in `PROJECT.md` and `plan/00-README.md`; `plan/00-README.md` → "Quality Bar & Anti-Debt Discipline" and "Cross-cutting conventions" are the authoritative process rules, and this file elaborates the two conventions below.

If anything here conflicts with `plan/00-README.md`, `plan/00-README.md` wins for process (gates, steps, debt tracking); this file wins for comment and line-wrapping style.

---

## Comments and line wrapping

### Comments explain *why*, never restate *what*

A comment that paraphrases the item's name, signature, type, or obvious behavior is noise and a future source of drift — delete it. The name, signature, and type already say what the code does. A comment earns its place only by adding something none of those can: the reason for a non-obvious choice, a constraint the code assumes but does not enforce, a hazard a reader would not anticipate, the origin of a magic constant, the invariant a function assumes, or a link to the issue/decision that motivated it.

This refines `plan/00-README.md` cross-cutting convention #4 ("No comments unless explicitly requested"). The spirit is the same — prefer self-describing names — but "no comments" is not literal: a comment that explains *why* is required and valuable; a comment that restates *what* is forbidden.

**Good** — explains why; information the code cannot carry (from `src/sdp.rs`):

```rust
/// Minimum SPS length carrying a NALU header byte plus the three profile/compat/level bytes (`sps[1..4]`) needed to derive `profile-level-id`, per RFC 6184 §8.1.
const PROFILE_LEVEL_ID_SPS_MIN_LEN: usize = 4;
```

The name says "min length"; the comment says *what that length is and why exactly four* (NALU header + three profile/compat/level bytes, per the RFC section). Delete it and a reader must reverse-engineer the byte layout. Note the comment is a single line — `///` does not exempt a comment from the wrapping rule below.

**Bad** — restates what the signature already says (removed in the one-time cleanup; do not reintroduce):

```rust
pub struct StreamSnapshot {
    /// Declared video width, if known.
    pub width: Option<u32>,
    /// Declared video height, if known.
    pub height: Option<u32>,
    /// Declared frame rate, if known.
    pub fps: Option<f32>,
}
```

`width: Option<u32>` already says "width, if known"; the struct-level doc already frames these as published-metadata fields. The field docs add nothing and drift if the fields are renamed.

When in doubt, ask: "If I delete this, does the reader lose information the code itself does not provide?" If yes, keep it; if no, cut it.

### No comments addressed to a future author

`// TODO: implement streaming later`, `// FIXME: …`, `// this is a placeholder for …`, `// will be done when …` do not belong in source unless they reference a tracked item. Communicate with future authors via `DEBT.md` (deferred/conditional work) or the relevant `plan/NN-*.md` step file (concrete assigned work) — not inline.

This reinforces `plan/00-README.md` Quality Gate item #7 (no `TODO`/`FIXME`/`HACK` without a matching `DEBT.md` entry) and extends it to prose forms ("later", "placeholder", "not yet … — see `DEBT.md`"): an inline "not yet …" marker is fine *only if* the `DEBT.md` entry or plan step it points to actually exists. A dangling "see `DEBT.md`" with no matching entry is a failed reference — either add the entry or drop the marker.

### Line wrapping

**Newlines carry semantic meaning only.** Do not insert a newline merely to keep a line under some width. A newline in prose marks a sentence or paragraph boundary; a newline in a struct separates logically grouped fields; a newline in a function separates distinct phases. A newline in the middle of a sentence, or in the middle of a single logical expression, is wrong even if the line is long.

**`rustfmt` is the sole authority for code formatting and wrapping.** Do not hand-wrap code to defeat it or to "match" a width. The project's `rustfmt.toml` sets `max_width = 10000` so rustfmt does *not* wrap — newlines in code are therefore always author-intentional structural breaks, never formatter-imposed width chops. If a line is genuinely too long, fix the code or the sentence; do not rely on the formatter to chop it, and do not hand-wrap to shorten it.

**The wrapping rule applies to *all* comments: `//`, `///`, and `//!`.** `rustfmt` does not touch comments, so comment wrapping is entirely the author's responsibility — there is no formatter to catch a hand-broken comment the way it catches hand-broken code. A `///` doc comment is not exempt from the rule just because it is a doc comment: the same newline semantics apply. Do not hand-wrap a `///` or `//` comment to stay under some width; write the sentence on one line and let the reader's editor soft-wrap. A hand-wrapped doc comment stays wrapped forever and drifts as the surrounding code changes. This applies to error messages, log strings, `///`/`//`/`//!` comments, and plan/design docs alike.

**One paragraph per line.** The granularity for prose (in comments, doc comments, and markdown) is one paragraph per source line: consecutive non-blank comment lines of the same prefix (`//`, `///`, or `//!`) are joined onto a single line; a blank comment line (e.g. a bare `///`) separates paragraphs and is preserved. Structural boundaries inside a comment block are also preserved as their own lines: a markdown list item (`- `, `* `, `N. `) starts a new line (its continuation lines join into the item), a markdown heading (`# `) gets its own line, and a byte-layout / ASCII diagram gets its own line(s). When in doubt, ask whether a newline marks a genuine sentence, paragraph, thought, or structural boundary — if not, it is an arbitrary wrap and must be rejoined.

Good (single line, let the editor wrap):

```rust
return Err(io::Error::new(io::ErrorKind::InvalidData, "could not load driver (no device / dlopen failed)"));
```

Bad (hand-broken mid-sentence for width):

```rust
return Err(io::Error::new(
    io::ErrorKind::InvalidData,
    "could not load driver (no device / \
     dlopen failed)",
));
```

The only valid reason to break a string literal across lines is a genuine structural boundary — e.g. one protocol line / one XML element / one HTTP header per continued line in a wire-format fixture. Those breaks carry meaning (they mirror the protocol's own line structure) and are kept.

### Automated enforcement

**No automated check enforces comment quality or wrapping policy.** "Reiterative comment" and "arbitrary wrap" are too fuzzy to lint without false positives that would make the gate a burden rather than a safety net, so they remain a **review judgment**, not a build-gate failure.

The mechanical subset is already covered by existing rules, not a new lint: `plan/00-README.md` Quality Gate item #7 forbids `TODO`/`FIXME`/`HACK` without a matching `DEBT.md` entry, and item #5 forbids commented-out code. `cargo fmt --check` (driven by `rustfmt.toml`) is the sole formatting gate and is mandatory in the Quality Gate.

`rustfmt.toml` records the wrapping decision (`max_width = 10000`) with an inline comment so the choice is auditable rather than an inherited default; re-evaluate it only if unwrapped lines are demonstrably hurting readability.

### Definition-of-done checklist (re-check every change)

Before declaring work done, in addition to `plan/00-README.md` → "Standard Quality Gate":

1. Re-scan touched modules for reiterative comments (paraphrasing a name/signature/type) and delete them. They accumulate silently.
2. Re-scan for inline future-author markers (`TODO`/`FIXME`/`XXX`/`HACK`/`later`/`placeholder`/`not yet …`) with no matching `DEBT.md` entry or plan step — remove or track them.
3. Re-scan touched `//`, `///`, and `//!` comments, prose, and string/format literals for mid-sentence wraps inserted for width and rejoin them onto one line (one paragraph per line). Preserve newlines that mark genuine sentence/paragraph/thought or structural (list-item, heading, diagram) boundaries.
4. Run `cargo fmt` (do not hand-format) and confirm `cargo fmt --check` is clean.

---

## History

A one-time cleanup pass established these conventions: reiterative doc-comments were deleted from public accessors/fields across `src/` (e.g. `StreamSnapshot` field docs, `WsConnection::into_inner`, `TlsStream::get_ref`/`get_mut`, `TagEvent` field docs); dangling "see `DEBT.md`" references in `src/protect_controller.rs` and `src/onvif_server.rs` were made good by adding matching `DEBT.md` entries (AVClient camera-confirmation; ONVIF firmware/serial learning); vague "a later step" markers in `src/camera_listener.rs` were tightened to explicit step-26/`DEBT.md` references; mid-sentence `\`-continued prose in `src/main.rs` and `tests/onvif_discovery.rs` was rejoined onto single lines. `rustfmt.toml` (`max_width = 10000`) was added and `cargo fmt` reflowed the tree accordingly. No logic changed; the host and `x86_64-pc-windows-gnu` builds, clippy (`-D warnings`), and the full `cargo test` suite are green. No automated comment/wrap lint was added (see "Automated enforcement" above); the decision is recorded here and in `plan/README.md` cross-cutting convention #4 and Quality Gate item #15, since the project has no separate ADR/decision-log folder.

A second pass extended the wrapping rule to *all* comments (`//`, `///`, `//!`) — the first pass had rejoined `\`-continued string literals and markdown prose but left hand-wrapped `///`/`//!` doc comments across `src/` and `tests/` untouched, and the AGENTS.md "Good" example itself violated the rule it stated. Every multi-line comment block in `src/` and `tests/` was rejoined to one paragraph per line (with blank-comment-line paragraph separators, list items, headings, and byte-layout diagrams preserved as their own lines); five `/`-separated token lists that had been broken mid-token across lines (e.g. `` `functionName`/ `messageId` ``) were rejoined without the spurious space; a byte-layout comparison diagram in `src/flv_parser.rs` that the mechanical rejoin had flattened into prose was restored to its structural lines. The markdown files (`PROJECT.md`, `DEBT.md`, `plan/README.md`, `plan/00–28`, `AGENTS.md`) were likewise rejoined to one paragraph per line. The host and `x86_64-pc-windows-gnu` builds, clippy (`-D warnings`), and the full `cargo test` suite remain green.

A third pass swept comment *purpose* (not just wrapping) across `src/` and `tests/`: ~40 reiterative doc comments were deleted — accessors/getters whose doc restated the fn name+return type (`print_banner`, `handle_flag`, `parse_method`, `handle_options`, `setup_ok`, `WsConnection::new`, `StreamState::new`, `VecSink::new`/`packets`/`into_packets`, `TcpInterleavedSink::new`, `UdpSink::new`, `SecBuffer::empty`, `ChainedReader::new`, `RetryReader::new`, `Reader::new`/`read_u8`/`read_u16`/`read_u32`, `Json::obj`/`uint`/`str_v`/`bool_v`/`get`, `trace_out`/`trace_in`, `payload_u64`/`payload_str`, `function_name`, `opcode_raw_with_fin`, `find_header_terminator`, `find_terminator`, `parse_port_range`, `char_from_alphabet`/`char_from_hex`, the two `install()` impls, `StreamStateInner`, the `RtspResponse` `status`/`status_text` field docs, the `OnvifConfig::onvif_port` field doc, the `AmfValue::Number` variant doc, `FALLBACK_HEIGHT`/`FALLBACK_FPS` restating-the-name consts, two `READ_CHUNK_BYTES` restating-the-name consts, one `RtspSessions::get`, and two `tests/common/mod.rs` helper docs); one inline `// Serve any buffered plaintext first.` restating the next-line conditional was deleted. A fresh audit confirmed all remaining `not yet`/`later`/`see DEBT.md` markers resolve to real `DEBT.md` entries (no dangling references). Genuine *why* comments (RFC/spec citations, hazard origins, RAII/Drop contracts, magic-constant origins, invariants, deliberately-omitted APIs) were preserved. No logic changed; the host and `x86_64-pc-windows-gnu` builds, clippy (`-D warnings`), and the full `cargo test` suite remain green.

A fourth pass swept `plan/…` / `step NN` / `DEBT.md` breadcrumbs from `src/`, `tests/`, `PROJECT.md`, `README.md`, `AGENTS.md`, and `flvproxy.ini.example`. Every citation to a plan step number or `plan/NN-…` file was either deleted (when it only restated what the code does) or rewritten as an inline statement (spec citation, behaviour summary, or the constant's rationale), so each retained comment still carries the *why* without depending on an external file. The `DEBT.md`-tracked AVClient camera-confirmation items in `protect_controller.rs` were replaced with the inline rationale ("payload shape reverse-engineered from the redalert reference, not yet confirmed against a live camera capture"). `PROJECT.md`'s and `README.md`'s pointers to `plan/README.md` were removed or retargeted; `AGENTS.md`'s live `plan/README.md` pointers were retargeted to the actual file `plan/00-README.md` (the plan folder was reorganized so `00-README.md` is the new process README). Historical mentions of `plan/`, `DEBT.md`, and the deleted old step files in `AGENTS.md` History are retained as past events. No logic changed; `cargo fmt --check`, clippy (`-D warnings`), `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` remain green.

