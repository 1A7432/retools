---
name: reworker
description: Delegate narrow IDA reverse-engineering legwork to a cheap flash-model worker with the `rew` command, then verify what comes back. Use when a reversing task splits into several independent lookups (triage a batch of functions, trace where a string or constant is used, map a call subtree, answer the same question for many addresses) and you are the orchestrating model. Not for single lookups; do those yourself with rekit.
---

# reworker

`rew` runs one worker: deepseek-v4.1-flash in DeepSeek Harness (`dsh`) headless
mode, attached to the same IDA database through ida-mcp, restricted to reading.
You give it a narrow task; it returns one JSON object with findings and the
addresses that back them. You stay responsible for the plan, for checking the
evidence, and for every change to the database.

The worker cannot see your conversation. Everything it knows comes from the
task you write.

## When to delegate

Delegate when the work is wide and shallow: many functions to triage, the same
question asked of many addresses, a call subtree to map, usages of a string or
constant to follow.

Do it yourself when it is one or two lookups, when the answer needs judgement
across everything you have learned so far, or when being wrong would be
costly. Workers are good at collecting and describing, weaker at deciding what
something is for.

Typical cost: one worker run takes from half a minute to four minutes and
50k-220k tokens (mostly cached input), however small the question, while a
`rekit` call takes a second. Single lookups are faster done directly. For pure
lookup tasks (collect callers, read data words, list call chains)
`--effort low` is reasonable.

What workers have shown they can do (seven trial tasks on a 14 MB Delphi PE,
all answered correctly): decide reachability of imports over a dozen functions
with the call chain for each; find a string's user and work out the registry
value name it builds; explain a small routine precisely; refuse a trap question
("none of them does"); build nested emulation inputs with `rekit.emu`; and
diagnose why an emulation stopped, replace the runtime's allocator, and finish
it. Where one went wrong, it was in naming a purpose (see "Verify").

## Run a worker

```bash
REW=~/.agents/skills/reworker/rew
$REW --db /path/to/binary_or.i64 --task task.json --out result.json
```

`task.json`:

```json
{
  "goal": "For each target, say what it does and which of them touch the network.",
  "targets": ["0x401000", "sub_402A10", "sub_40F3C0"],
  "questions": ["Which targets call socket or WinHTTP imports, directly or one level down?"],
  "context": "Delphi PE. sub_40F3C0 is reached from the service entry point.",
  "max_calls": 25,
  "max_findings": 8,
  "mode": "strict"
}
```

Only `goal` is required. For a quick one, skip the file:

```bash
$REW --db sample.bin --goal "Where is the string 'cfg.ini' used and what reads it?" --target 0x8004b4
```

Options: `--mode strict|free`, `--max-calls N` (hard budget of execute_python
calls, default 25), `--max-findings N` (default 8), `--max-chars N` (budget
for the printed result, default 6000), `--effort low|high|max` (default high),
`--model ID`, `--context TEXT`, `--question TEXT` (repeatable),
`--timeout SECONDS` (wall clock for the whole run, default 600), `--out FILE`.
Command-line values override the task file.

Write the task the way you would brief a capable colleague who has never seen
this binary: what you want to know, which addresses to start from, what you
already know that saves them time, and what would count as done. One task, one
question cluster; split unrelated questions across workers. Six calls were
enough for "describe this function and its callees" in testing; a wide triage
needs more.

Keep tasks narrow. An open-ended "work out what this program does" run on a
small obfuscated binary took 9 to 16 minutes and 1.2M to 2.4M tokens, ten
times a pointed question, and a pointed follow-up was still needed.

What a blind benchmark (58 questions on obfuscated and cryptographic puzzle
binaries) showed about worker answers: values a worker computed by emulation
were right; what went wrong was (1) a formula stated without being recomputed
(a rotate read as an add), (2) "the constants are all standard" after an
eyeball comparison of a 64-entry table with one altered entry, (3) a long hex
string copied with characters missing, and (4) "can never execute" answered
as "is not in the table". So: recompute any formula yourself against a real
output, diff tables against the reference programmatically, take long values
from the tool output rather than from the worker's prose (workers now quote
them by reference, and rew flags long values that match no tool output; see
"Read the result"), and when an
emulated result contradicts a standard algorithm, look for a changed constant
before suspecting the emulator. Since then workers have been given what they lacked: `rekit.run` (emulate the
whole program on an input), `rekit.crypto` (known tables and where they
deviate), `rekit.calc` (a restricted scratchpad to recompute formulas, decrypt
and test altered constants), and value references in their answers. Say in
the task when you expect one of them to be used ("confirm with rekit.run",
"check the table with rekit.crypto", "recompute your formula with
rekit.calc").

Define counting conventions and any other ambiguous term in the task. "Within
two call levels" was read as a different depth than intended in a trial; say
whether the target itself is level 0 or 1, whether thunks and library helpers
count, and so on. Asking for the exact call chain behind each claim is good
practice: it is what made that mismatch visible.

To run several at once, start each `rew` in the background with its own
`--out result-N.json` and read the files when they finish. Five workers at
once on one database ran without trouble; they share ida-mcp's idalib worker,
so each lookup is serialised there, which is not the slow part.

### Modes

- `strict` (default): `execute_python` accepts only `rekit` calls with literal
  arguments (plus the three lines that load rekit), including `rekit.emu` for
  function-level emulation. Plain IDAPython, assignments to subscripts, loops
  and `print` are refused. The worker cannot write to the
  database or guess at IDA API names. Use this unless you have a reason not to.
- `free`: plain IDAPython is allowed for reading, for lookups rekit does not
  cover (raw data words, VMT walks, a ctree, a custom table). Calls that modify
  the database or reach outside IDA are refused by name. That check is a
  guardrail against a careless model, not a sandbox, so use `free` only when
  the task needs it, and say in `context` what rekit lacks.

In both modes the worker sees only the ida tools `open_database` (pinned to
`--db`), `list_databases`, `execute_python` and `reference`. `save_database`
and `close_database` are not offered, and `execute_python` with an
`instance_id` (another open database) is refused. A refused call comes back to the worker
as an error it can read, and once the budget is spent every further
`execute_python` call is refused with "write your result now".

## Read the result

```json
{
  "status": "ok",
  "summary": "...",
  "findings": [
    {"claim": "...", "evidence": ["0x401a2c", "sub_402A10+0x38"],
     "confidence": "high", "grounded": true},
    {"claim": "sub_495BD0 writes dc8f7629... to out", "evidence": ["0x495c08 ret"],
     "confidence": "high", "grounded": true,
     "filled": ["{{7.buffers.top[name=out].hex}}", "{{7.stop.at}}"]},
    {"claim": "the key is 7b1c0e9f33a2d4c85e6f0a1b2c3d4e5f ...", "evidence": ["0x401b00"],
     "confidence": "medium", "grounded": true, "unmatched": true}
  ],
  "unknowns": ["..."],
  "needs": ["..."],
  "worker": {
    "valid": true, "problems": [], "mode": "strict",
    "model": "deepseek-v4.1-flash", "effort": "high", "backend": "dsh",
    "seconds": 121.5, "tool_calls": 9, "refused": 2,
    "budget": {"max_calls": 6, "used": 6},
    "tokens": {"inputTokens": 25155, "outputTokens": 18778, "cacheReadTokens": 82688, "totalTokens": 126621},
    "session": "session-...", "attempts": 2, "exit": [0, 0], "reason": {"kind": "completed"},
    "audit": {"ok": true, "breaches": [], "notes": []},
    "filled": [{"ref": "{{7.buffers.top[name=out].hex}}", "in": "findings[1].claim",
                "at": [18, 378], "chars": 360}, "..."],
    "unmatched": {"total": 1, "asked": true, "values": [
      {"value": "7b1c0e9f33a2…2c3d4e5f", "chars": 32, "in": ["findings[2].claim"]}]},
    "run_dir": ".../tmp/rew-runs/20261114-052756-sample.bin-428c",
    "ledger": {"path": ".../findings/sample.bin.jsonl", "ids": ["f-37111591a2", "..."]}
  }
}
```

`rew run` prints the result as one line of JSON. Exit code: 0 valid, 1 invalid
result (including timeout), 2 the worker did not start (bad task, missing
database, profile missing: run `rew setup`), 3 audit failure.

The worker is asked for a short answer: the direct answer in `summary`, at
most `max_findings` findings with one- or two-sentence claims, and evidence
entries that are an address or ref plus a few words (at most four per
finding). A reply with more findings than allowed, or an evidence entry
without an address, gets one correction round. If the printed result would
still exceed `--max-chars`, rew shortens it: evidence entries to the address
token plus about 60 characters, then claims to about 400, then it drops the
lowest-confidence findings. Nothing is cut silently: a `truncated` object
lists each step, the dropped findings (index, confidence, ledger id),
`findings_total`, and `full_result`, the path of the complete result in the
run directory. Substituted values count toward the budget, and a cut never
splits one: the text stops before it with `…[{{ref}}: N chars omitted]`, and
`truncated.filled_omitted` lists each value left out; read it from
`full_result`. `--out` gets the same shortened result; the ledger always gets
every finding in full.

- `grounded: false` means none of the cited addresses appeared in the task or
  in the worker's own tool results (read in full from the guard log and
  decoded, so disassembly line addresses count). Treat that finding as
  unsupported. Values below 0x1000 (struct offsets, constants) are not
  addresses for this purpose. `grounded: true` only says an address was seen,
  not that the claim is right.
- `worker.valid: false` means the reply never fitted the contract even after
  one correction (the same session is resumed once with the problems listed);
  `worker.problems` says why and `worker.raw` holds the reply text. Re-run with
  a narrower task rather than salvaging it.
- `worker.audit.ok: false` (exit 3) means the run showed something the setup
  should make impossible: a call to a non-ida tool, an ida result that did not
  pass through the guard proxy, or ida-mcp answering a refused call. Do not use
  the result; run `rew doctor` and look at `run_dir`. A tool the model merely
  invented, which dsh rejected as unknown, is listed under `audit.notes` only.
- Exact values. Each `execute_python` result the worker sees is headed
  `[call N of MAX]` (refused and over-budget calls get no number; `call_no`
  in `guard.jsonl`). In its JSON the worker writes `{{N.path}}`, a path into
  what call N returned (`.key`, `[index]`, `[field=value]`, `[a:b]` on a
  string, `["odd.key"]`), and rew substitutes the exact value before
  validation. `worker.filled` lists what was substituted and where
  (`in` uses 0-based indexes, `at` is the character range in that string
  of the full result;
  at most 20 entries, `filled_total` when there are more) and each finding
  carries its references under `filled`. Those values are byte-exact copies
  of tool output; whether they are the right values is still the worker's
  claim. A reference that does not resolve is a contract problem and gets a
  correction round naming the keys that exist.
- `worker.unmatched` lists long literals (16+ hex digits, or base64-like
  runs) left in the summary or claims that appear nowhere, ignoring case and
  separators, in the task, the tool results or the worker's own call
  arguments; findings containing one have `unmatched: true`. Each is either
  something the worker computed or a typing slip, and rew cannot tell which,
  so the result is not rejected. An entry with `near` is almost certainly a
  slip: it names the call (and usually the exact `ref`) holding a value
  within a few characters of it; take that value from the tool output
  (`run_dir/guard.jsonl`) instead. Without `near`, treat the value as
  unverified and recompute it before relying on it. `asked: true` means one
  correction round asked the worker to replace each such value with a
  reference or say what it was derived from, and these remained;
  `kept_earlier_reply` means the reply to that question did not validate and
  the earlier valid reply was kept. At most 8 values are shown (`total`
  counts all).
- `needs` is the worker telling you what it could not do: renames it would
  suggest, lookups its mode or budget refused, side discoveries. Decide on
  each yourself.
- `status: "partial"` usually means the call budget ran out. Raise
  `--max-calls` or split the task.
- `run_dir` keeps everything: `prompt.txt`, `events-N.jsonl` (dsh stream),
  `guard.jsonl` (every tool call with its full result), `result.json` (the
  complete, unshortened result), and the dsh session log under `dsh/sessions`.

## Findings ledger

After a valid run each finding is appended to
`findings/<db file name without .i64>.jsonl` (directory overridable with
`REKIT_FINDINGS`) with a stable id, `source` such as
`worker:deepseek-v4.1-flash:strict`, the goal, and `verified: null`. The
ledger is append-only; later records win. `rekit/_notes.py` reads it
(`load(root_filename)`, `in_range(notes, lo, hi)`).

Record your verdict after checking a finding:

```bash
$REW verify --db sample.bin --id f-37111591a2 --ok --note "read sub_B5EB8C, matches"
$REW verify --db sample.bin --id f-1a2b3c4d5e --reject --note "callee is sub_57CDB8, not sub_571878"
```

Record a finding you established yourself (stored as `source: orchestrator`,
`verified: true`):

```bash
$REW note --db sample.bin --claim "0xB5DA48 is the VMT of TsCheckBox" --evidence 0xB5DA48 0xB5DA68 --confidence high
```

## Verify before you rely on it

A worker's finding is a lead with addresses attached, not a fact.

- Check the evidence for anything you will build on: `rekit.fn` or `rekit.code`
  at the cited address takes one call. Check every high-impact claim, and a
  sample of the rest, then record the verdict with `rew verify`.
- Be most sceptical of claims about purpose ("this is the C2 beacon") and of
  `low` confidence items. Claims about structure (calls, strings, constants)
  are usually reliable when grounded.
- If two findings disagree, read the code yourself.

An example from the trial: a worker reported that a function "is the binary's
cross-process injection routine" because it calls OpenProcess and
VirtualAllocEx. Every API in the claim was really called. Reading the code
showed no WriteProcessMemory and no remote thread: it finds the taskbar's
toolbar window, sends it TB_GETBUTTON messages, and reads the answers back
with ReadProcessMemory, a common way to locate one's own taskbar button. The
facts were right and the label was wrong, and the label is what would have
ended up in a report.

Only you write to the database. Apply renames, comments and types yourself
after checking, and keep unverified worker output out of names: a wrong name
misleads every later reader, including the next worker.

When you report to the user, say which conclusions you verified yourself and
which rest on worker findings alone.

## Setup and health

```bash
$REW setup     # create or refresh ~/.dsh/profiles/re-worker from profile/cordis.patch.yml
$REW doctor    # dsh version, profile, composed config, proxy self-test,
               # the exact tool list dsh offers the model, ida-mcp
```

`rew run` refuses to start when the profile is missing or differs from the
repo patch. Run `rew doctor` after any DeepSeek Harness update: it boots the
profile against a fake model and fails if anything but the four ida tools is
offered.

## How it is put together

- `rew`: the launcher. Builds the prompt (`contract.py`), runs the backend,
  validates, retries once, audits, writes the ledger (`ledger.py`).
- `refs.py`: `{{N.path}}` references (parse, resolve, fill) and the check
  for long values that match no tool output, with near-miss detection.
- `backend_dsh.py`: everything dsh-specific (profile, per-run `--patch`
  overlay, headless command line, event-stream parsing, doctor checks).
- `guardproxy.py`: the worker's MCP server. It runs the real
  `ida-mcp stdio --agent=dsh-worker` as a child, filters `tools/list`, checks
  every `tools/call` with `guard.py`, enforces the call budget, numbers each
  relayed `execute_python` call, logs every call in full, and fails closed.
- `profile/cordis.patch.yml`: the dsh profile layer (provider, model, every
  non-ida tool row disabled, mcp-ida row pointing at the proxy).
- Tests: `test_guard.py`, `test_contract.py`, `test_refs.py`, `test_guardproxy.py`,
  `test_rew.py` (fake dsh), `test_integration.py` (real dsh, fake model and
  fake ida-mcp), `../rekit/test_notes.py`.
