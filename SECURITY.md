# Security Policy

## Clean-Room Guarantee

`StarCouncil` is strictly zero-dependency (Python 3.10+ stdlib only) and runs `starcouncil sanitize-lint` on every push via CI to guarantee zero host paths, internal/CGNAT IPs, session identifiers, or credentials in public commits.

## Defensive Design Controls

1. **Symlink & Traversal Safety**: All state writes use `os.O_NOFOLLOW` + regular-file `S_ISREG` verification + atomic temp-file `os.replace`.
2. **Remote SSH Hygiene**: Zero `shell=True`; commands wrap remote paths with `shlex.quote` (`BatchMode=yes`, `ForwardAgent=no`) and enforce `<= 64KB` strict 7-bit ASCII JSON over `stdin` with explicit host/seat allowlists.
3. **Fail-Closed External Gate**: Outages/timeouts in external review CLIs return `OUTAGE_FAIL_CLOSED` and block approval.
4. **Session-Scoped HMAC Pseudonymization**: Use `starcouncil review --pseudonymize-file` before sharing trace logs with external models.

## Reporting Vulnerabilities

Please report security issues privately via GitHub Security Advisories at `https://github.com/Ziqi/starcouncil/security/advisories/new`.
