# Security Policy

## Supported versions

zinit is small enough that a fix ships as a
new patch release, and there are no backports to older minors.
Any fixes will be included in the next release.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab → "Report a
vulnerability"), not a public issue or pull request, so the report stays
private until a fix is out. If that is not an option, mail
`ComixHe1895@outlook.com`.

Please include what you ran, what you expected, what you observed, and whether
it reproduces in a container with a stock runtime.

## Scope

In scope: the shipped binary (argument and environment parsing, signal
handling, reaping, the shutdown path), the build tooling (`build.zig`,
`tools/`), and the release pipeline (workflows, packaging, signing).

Out of scope: the container runtime, the kernel, and whatever workload you put
behind zinit — a workload that ignores `SIGTERM` is not a zinit bug. zinit
trusts the arguments and environment it is handed, the way a runtime trusts its
own configuration, so a name from them that lands in a log line is echoed
verbatim: log injection through an argument is out of scope with it.

## Vulnerability management and disclosure

A first reply is best effort within a week; there is no bug bounty. From there
the report is triaged against [Scope](#scope), fixed on `main`, and shipped in
a patch release — a released version is never replaced, so the fix is always a
new one. It becomes a
[security advisory](https://github.com/ComixHe/zinit/security/advisories) with
a CVE requested through GitHub, and you are credited unless you would rather
not be. Fixes have no fixed deadline: give us time to ship one before
disclosing, and we will not sit on a report longer than needed.

Good-faith research that follows this policy is authorised; we will not pursue
it.
