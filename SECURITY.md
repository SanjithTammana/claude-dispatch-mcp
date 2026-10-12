# Security policy

This project is a security boundary, so reports are welcome. That includes a way for a caller or
a dispatched Claude turn to:
- run commands;
- reach paths outside `cd`;
- change files without a `VIOLATION`;
- leave processes running after a confirmed cleanup;
- alter the dispatcher's own state.

Please report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, not in a public issue. Include the Claude Code version (`claude --version`), the
Windows build, and a minimal reproduction.

Known limits that are by design are listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#limits).
