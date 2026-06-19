# Step 01 — Logging and Config

**Depends on:** Step 00.

## Goal

Two small, self-contained, fully testable modules: a file logger with rotation
and an INI config parser. Both are pure logic / `std::io` only.

## Tasks — `src/logging.rs`

1. A `Logger` struct holding:
   - `path: PathBuf`
   - `max_bytes: u64` (default 10 * 1024 * 1024)
   - `inner: Mutex<File>` (or `Mutex<BufWriter<File>>`)
2. `Logger::open(path) -> io::Result<Logger>`.
3. `Logger::log(level: Level, msg: &str)` writes one line:
   `YYYY-MM-DD HH:MM:SS.mmm [LEVEL] msg\n`.
   - Timestamps via `SystemTime` + a small epoch-to-civil converter (no `chrono`).
   - Levels: `INFO`, `WARN`, `ERROR` (an enum).
4. Rotation: before each write, if current file size > `max_bytes`, close,
   rename to `<path>.1` (overwriting prior backup), reopen fresh.
5. Convenience macros or free functions: `log_info!`, `log_warn!`, `log_error!`
   are optional — a plain `logger.log(Level::Info, "...")` API is fine.
6. A global singleton is acceptable but keep the `Logger` itself testable via
   direct construction against a `tempdir`-style path (create a unique file in
   `std::env::temp_dir()` for tests — no `tempfile` crate).

## Tasks — `src/config.rs`

1. `struct Config { listen_port: u16, rtsp_port: u16, onvif_port: u16,
   onvif_discovery: bool }` with the defaults from `PROJECT.md` (7550/8554/8080/true).
2. `Config::default()`.
3. `Config::from_file(path: &Path) -> io::Result<Config>`:
   - Read text, split lines, ignore blank/`#`-comment lines.
   - Support a single `[server]` section header (ignore other sections).
   - Parse `key = value` pairs; `#` after value is a comment — strip it.
   - Unknown keys: ignore (or log warn via a passed-in callback — keep parser
     dependency-free, just ignore for now).
   - Malformed line: skip with no panic.
   - `true`/`false` parsed case-insensitively for bool fields.
4. `Config::load_or_default(path: &Path) -> Config` — returns default if file
   missing or unreadable.

## Validation (automated) — `tests/logging.rs`, `tests/config.rs`

Logging:
- Write ~50 short lines, assert file exists and contains them in order.
- Set `max_bytes` tiny (e.g. 200), write enough to trigger rotation, assert
   `<path>.1` exists and the active file is smaller than the rotated one.
- Assert each line begins with a timestamp matching
   `^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \[(INFO|WARN|ERROR)\] `.

Config:
- Parse a string (write to temp file) with the example INI from `PROJECT.md`;
   assert all four fields read correctly.
- Parse with inline `# comments`, blank lines, an unknown key, a missing
   `[server]` header — assert defaults applied where missing and no panic.
- `load_or_default` on a nonexistent path returns `Config::default()`.
- Bool parsing: `True`, `FALSE`, `1`/`0` is **not** required — only `true`/
   `false` (case-insensitive). Document and test the boundary.

## Quality Gate (mandatory — step is not complete until this passes)

Run the **Standard Quality Gate** from `plan/README.md`. Then **step back and review the whole codebase**, not just the diff:

- Does this change respect the module boundaries in `PROJECT.md`, or did you bend them? If bent, refactor now.
- Did consuming this step reveal that an earlier module's API is awkward, mis-named, or leaky? Go back and fix that module — do not paper over it here.
- Any new duplication across modules? Extract a shared helper into the owning module.
- Are logging, error, and test styles consistent with the conventions established by earlier steps?
- Did you introduce a `// TODO` / `// FIXME` / `// HACK`, commented-out code, or a magic number? Remove it, name it as a constant, or log it in `DEBT.md`.

**Hard rules:**
- If the gate fails, you do **not** proceed to the next step.
- If passing it properly requires reworking an earlier step, do that rework now — **iterating or redoing is preferred over hacking to move on.**
- A step that "works but feels hacky" is a failed step. Reopen it.

## Debt notes

If anything was deferred (a workaround, a "good enough for now", an unclear decision), append a line to `DEBT.md` at the repo root (create the file if absent — see `plan/README.md` for the format):

`step NN | <file>:<area> | <what> | <FIX NOW | TRIGGER: ...>`

- `FIX NOW` items must be resolved before the next dedicated review (`06r` / `11r` / `16r` / `19`).
- `TRIGGER:` items must name the concrete future event that forces revisiting them.
- No silent hacks: if you hacked it, log it. If you can fix it now, fix it now and don't log it.

## Do not

- No `chrono`, `log`, `tracing`, `serde`, `tempfile` crates. `std` only.
