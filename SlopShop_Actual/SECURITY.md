# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in sastbench itself (not in the benchmark datasets it evaluates), please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email your report to the repository maintainers (see commit history for contact info), or use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
3. Include steps to reproduce, impact assessment, and any suggested fixes.

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for confirmed vulnerabilities.

## Scope

sastbench is a benchmarking tool, not a production security service. The following are in scope:

- **Path traversal** in workspace preparation or cache management
- **Code injection** via agent output parsing (SARIF/JSON/CSV)
- **XSS** in HTML report generation
- **Command injection** in platform adapters (Docker, shell commands)

The following are **not** in scope:

- Vulnerabilities in the benchmark datasets themselves (Juliet, BigVul, etc.) — those are third-party data
- Issues that require the attacker to already have local code execution
- Denial of service via large benchmark datasets (this is expected behavior)

## Known Security Considerations

- **HTML reports**: Generated with Jinja2 autoescape enabled to prevent XSS from agent-generated content.
- **Cache directory**: Downloads are validated and paths are resolved to prevent traversal.
- **Docker platform**: Commands are sanitized with `shlex.quote()` to prevent injection.
- **Agent workspaces**: Ground truth is stored outside the workspace to prevent agents from reading answers.
