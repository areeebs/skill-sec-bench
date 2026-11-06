# Sample schema

Every sample is a directory under `corpus/malicious/` or `corpus/benign/`,
named `<id>-<slug>` (e.g. `0001-prompt-injection-ignore-instructions`).

It contains exactly two files.

## `SKILL.md`

The skill or MCP tool definition that a scanner inspects. It should look like a
real definition: YAML front matter (`name`, `description`, optionally
`allowed-tools` / `parameters`) followed by a human-readable body. For malicious
samples, the attack lives somewhere in this file.

## `meta.json`

Ground-truth metadata:

```json
{
  "id": "0001",
  "label": "malicious",
  "category": "prompt-injection",
  "technique": "instruction-override-hidden-comment",
  "severity": "high",
  "description": "One line on what the sample does and why it is (or isn't) malicious.",
  "references": ["https://..."]
}
```

| field         | required | notes                                                                 |
|---------------|----------|-----------------------------------------------------------------------|
| `id`          | yes      | zero-padded, unique, matches the directory prefix                     |
| `label`       | yes      | `"malicious"` or `"benign"` — must match the parent folder            |
| `category`    | yes      | e.g. `prompt-injection`, `tool-poisoning`, `data-exfiltration`, `permission-mismatch`; `none` for benign |
| `technique`   | yes      | short slug for the specific method; `none` for benign                 |
| `severity`    | yes      | `critical` / `high` / `medium` / `low` / `none`                       |
| `description` | yes      | one sentence                                                          |
| `references`  | no       | URLs documenting the technique                                        |

The directory label and `meta.json`'s `label` must agree; `--self-test`
enforces this.
