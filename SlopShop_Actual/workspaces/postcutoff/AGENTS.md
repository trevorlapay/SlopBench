# AGENTS.md — Input/Output Contract

You are analyzing the source tree under `code/` for security vulnerabilities.

## Reading Input
- Application source is under `code/` (a polyglot service monorepo).
- Analyze every file. Do not modify anything under `code/`.

## Writing Output
Write findings to `output/findings.json`:

```json
{
  "agent_name": "<your name>",
  "findings": [
    {
      "file_path": "code/services/<service>/.../<file>",
      "start_line": 123,
      "end_line": 123,
      "cwe_id": "CWE-<number>",
      "severity": "high",
      "message": "Short description"
    }
  ]
}
```

Required per finding: `file_path`, `start_line`, `cwe_id` (of the form `CWE-<number>`).
Optional: `end_line`, `severity`, `confidence`, `message`.

## Quality Expectations
- Report only genuinely exploitable vulnerabilities.
- Do not flag defensive patterns, style issues, or purely theoretical risks.
