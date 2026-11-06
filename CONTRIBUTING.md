# Contributing

The value of this benchmark is breadth and correct labels. New attack
techniques and new "benign-but-scary" edge cases are the most useful additions.

## Add a sample

1. Pick the next free id and create a directory:
   - malicious: `corpus/malicious/<id>-<slug>/`
   - benign: `corpus/benign/<id>-<slug>/`
   (malicious ids start at `0001`, benign ids at `1001`.)

2. Add `SKILL.md` — a realistic skill/MCP definition. For malicious samples,
   embed the attack in a way a real one would. Keep it **inert**: static text
   only, and use reserved example domains (`example.com`, `example.net`) for any
   network reference. No working malware, no real credentials, no live hosts.

3. Add `meta.json` following [SCHEMA.md](SCHEMA.md). The `label` must match the
   folder.

4. Validate:
   ```bash
   python3 harness/run_benchmark.py --self-test
   ```
   CI runs the same check on every pull request.

## What makes a good benign sample

The easy malicious samples are already caught by keyword matching. The samples
that actually discriminate between good and bad scanners are **benign ones that
contain suspicious-looking words for legitimate reasons** — a privacy policy
that mentions `~/.ssh`, a tutorial that shows an `ignore previous instructions`
example, a logging tool that reads environment variables on purpose. These keep
scanners honest. Please add them.

## Labeling guidance

- Label by *intent and effect*, not vocabulary.
- If a sample is genuinely ambiguous, it probably belongs in a future
  `corpus/ambiguous/` tier rather than being forced into malicious/benign.
- Cite a reference in `meta.json` when the technique is documented publicly.
