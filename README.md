# skill-sec-bench

A **benchmark** for security scanners that inspect AI *skills* and *MCP (Model Context Protocol) servers*.

There are now dozens of tools that claim to detect malicious skills and MCP
tool definitions — prompt injection, tool poisoning, data exfiltration, and so
on. What's missing is a **shared, labeled test set** to measure whether any of
them actually work. `skill-sec-bench` is that test set, plus a small harness
that scores any scanner on it.

> **Why this exists:** scanner authors publish detection-rule counts ("268
> rules!") but no precision/recall numbers, because there's nothing neutral to
> measure against. A benchmark lets users compare tools and lets authors catch
> regressions.

## What's in here

```
corpus/
  malicious/   skill/MCP definitions that SHOULD be flagged
  benign/      legitimate definitions that should NOT be flagged
harness/
  run_benchmark.py   runs a scanner over the corpus and scores it
```

Each sample is a directory containing:

| file        | purpose                                                        |
|-------------|----------------------------------------------------------------|
| `SKILL.md`  | the definition a scanner inspects                              |
| `meta.json` | ground-truth label and metadata (see [SCHEMA.md](SCHEMA.md))   |

The parent folder (`malicious/` or `benign/`) is the ground-truth label. The
**positive class is "malicious"**: a good scanner *flags* malicious samples and
*leaves benign ones alone*.

## Quick start

Run the built-in naive baseline scanner (no dependencies needed):

```bash
python3 harness/run_benchmark.py
```

Evaluate **your own** scanner — any command that inspects a file. `{path}` is
replaced with the sample's `SKILL.md`. A sample counts as *flagged* if the
command exits non-zero, or prints a line matching `--flag-regex`:

```bash
python3 harness/run_benchmark.py --scanner "my-scanner --file {path}"
```

Check that the corpus is well-formed (what CI runs):

```bash
python3 harness/run_benchmark.py --self-test
```

## How scoring works

For the positive ("malicious") class:

- **Recall** — of the malicious samples, how many did the scanner catch? Low
  recall = dangerous skills slip through.
- **Precision** — of everything the scanner flagged, how much was actually
  malicious? Low precision = false alarms that users learn to ignore.
- **F1** — the balance of the two.

A scanner that flags *everything* gets perfect recall but terrible precision.
A scanner that flags *nothing* gets perfect precision on benign samples but
zero recall. The corpus deliberately includes benign samples that *look*
suspicious (e.g. a password tool that mentions `~/.ssh` only to say it never
touches it) to punish lazy keyword matching.

## Safety note

Every malicious sample is an **inert, static text file** describing a
well-documented attack pattern. Nothing here is executable malware, and all
network references use reserved example domains (`example.com`, `example.net`).
The corpus exists so defensive tools can be tested and improved.

## Contributing

New attack techniques appear constantly — that's the whole point of maintaining
this. See [CONTRIBUTING.md](CONTRIBUTING.md) to add a sample.

## License

[MIT](LICENSE).
