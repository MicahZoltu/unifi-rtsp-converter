# AGENTS.md — contributor guide for agents and humans

This is the repository-wide contributor doc for code-quality conventions that apply to *every* change.

---

## Comments and line wrapping

### Comments explain *why*, never restate *what*

A comment that paraphrases the item's name, signature, type, or obvious behavior is noise and a future source of drift — delete it. The name, signature, and type already say what the code does. A comment earns its place only by adding something none of those can: the reason for a non-obvious choice, a constraint the code assumes but does not enforce, a hazard a reader would not anticipate, the origin of a magic constant, the invariant a function assumes, or a link to the issue/decision that motivated it.

**Good** — explains why; information the code cannot carry (from `src/sdp.rs`):

```rust
/// Minimum SPS length carrying a NALU header byte plus the three profile/compat/level bytes (`sps[1..4]`) needed to derive `profile-level-id`, per RFC 6184 §8.1.
const PROFILE_LEVEL_ID_SPS_MIN_LEN: usize = 4;
```

The name says "min length"; the comment says *what that length is and why exactly four* (NALU header + three profile/compat/level bytes, per the RFC section). Delete it and a reader must reverse-engineer the byte layout.

**Bad** — restates what the signature already says:

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

### Line wrapping

**Newlines carry semantic meaning only.** Do not insert a newline merely to keep a line under some width. A newline in prose marks a sentence or paragraph boundary; a newline in a struct separates logically grouped fields; a newline in a function separates distinct phases. A newline in the middle of a sentence, or in the middle of a single logical expression, is wrong even if the line is long.

**`rustfmt` is the sole authority for code formatting and wrapping.** Do not hand-wrap code to defeat it or to "match" a width. The project's `rustfmt.toml` sets `max_width = 10000` so rustfmt does *not* wrap — newlines in code are therefore always author-intentional structural breaks, never formatter-imposed width chops. If a line is genuinely too long, fix the code or the sentence; do not rely on the formatter to chop it, and do not hand-wrap to shorten it.

**The wrapping rule applies to *all* comments: `//`, `///`, and `//!`.** `rustfmt` does not touch comments, so comment wrapping is entirely the author's responsibility — there is no formatter to catch a hand-broken comment the way it catches hand-broken code. A `///` doc comment is not exempt from the rule just because it is a doc comment: the same newline semantics apply. Do not hand-wrap a `///` or `//` comment to stay under some width; write the sentence on one line and let the reader's editor soft-wrap. A hand-wrapped doc comment stays wrapped forever and drifts as the surrounding code changes. This applies to error messages, log strings, `///`/`//`/`//!` comments, and plan/design docs alike.

**One sentence per line in code.** The granularity for prose in code (e.g., in comments, doc comments, strings) is one sentence per source line. Structural boundaries inside a comment block are also preserved as their own lines: a markdown list item (`- `, `* `, `N. `) starts a new line (its continuation lines join into the item), a markdown heading (`# `) gets its own line, and a byte-layout / ASCII diagram gets its own line(s). When in doubt, ask whether a newline marks a genuine sentence, paragraph, thought, or structural boundary — if not, it is an arbitrary wrap and must be rejoined.

**One paragraph per line in documentation.** The granularity for prose in documentation (e.g., markdown files) is one paragraph per line.

Good (single line, let the editor soft wrap if necessary):

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

### Definition-of-done checklist (re-check every change)

Before declaring work done:

1. Re-scan touched modules for reiterative comments (paraphrasing a name/signature/type) and delete them. They accumulate silently.
2. Re-scan for inline future-author markers (`TODO`/`FIXME`/`XXX`/`HACK`/`later`/`placeholder`/`not yet …`).
3. Re-scan touched `//`, `///`, and `//!` comments, prose, and string/format literals for mid-sentence wraps inserted for width and rejoin them onto one line (one paragraph per line). Preserve newlines that mark genuine sentence/paragraph/thought or structural (list-item, heading, diagram) boundaries.
4. Run `cargo fmt` (do not hand-format) and confirm `cargo fmt --check` is clean.
