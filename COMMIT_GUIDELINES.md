# Commit Message Guidelines – Snypshark

To maintain a consistent and professional Git history in the Snypshark project, all commits should follow a standardized format. This helps contributors quickly understand the purpose of changes and keeps the project history organized.

---

## Commit Types

| Prefix  | Description |
|---------|-------------|
| `add [feature-name]` | Introduce a new feature, module, or functionality. Example: `add tcp-analysis-module` |
| `setup [feature-name]` | Configure or initialize environments, settings, or dependencies. Example: `setup virtualenv` |
| `delete [feature-name]` | Remove obsolete files, modules, or features. Example: `delete old-parser` |
| `fix [feature-name]` | Correct a bug or issue in the codebase. Example: `fix packet-parsing-error` |
| `update [feature-name]` | Improve or modify existing code, documentation, or dependencies. Example: `update README` |
| `tofix [feature-name]` | Temporary change that needs further fixing later. Example: `tofix progress-bar-bug` |

---

## Examples for Snypshark

- `add pcap-parser` → Added a new PCAP parsing module.
- `setup analyzer-ui` → Initialized the interactive CLI menu.
- `delete legacy-utils` → Removed deprecated helper functions.
- `fix anomaly-detection` → Fixed the anomaly scoring bug.
- `update export-json` → Updated JSON export formatting.
- `tofix top-talkers` → Temporary solution applied; needs optimization later.

---

## Best Practices

1. Keep commit messages short and descriptive (50–72 characters recommended).
2. Use imperative mood (`Add`, `Fix`, `Update`) instead of past tense.
3. Reference issues or tickets if applicable (e.g., `fix #23`).
4. Resolve all merge conflicts before committing.
5. Avoid committing large binary files directly; use exports if needed.

---

By following this standard, contributors to Snypshark can maintain a clean, understandable, and traceable project history, making collaboration smoother and more professional.
