# Security Policy

## Supported Versions

Only the latest minor release line of `parser-lineage-analyzer` receives security
updates. Older versions may be patched at the maintainer's discretion when the
fix is low-risk.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** via GitHub's security
advisory workflow:

  https://github.com/JudgeZ/parser-lineage-analyzer/security/advisories/new

Do **not** open a public issue, pull request, or discussion for security
reports. The GitHub Security Advisory form linked above is the only
supported channel; please do not attempt to disclose through other means.

When reporting, please include:

- A description of the issue and its impact.
- A minimal reproduction (input file, command, or test case).
- The affected version (`parser-lineage-analyzer --version` or the installed
  wheel filename).
- Whether the native extension is involved. The extension is active by
  default and can be disabled by setting `PARSER_LINEAGE_ANALYZER_NO_EXT=1`;
  please indicate whether the issue reproduces with the extension enabled,
  disabled, or both.

## Response Targets

- Acknowledgement of the report: within 2 business days.
- Initial triage and severity assessment: within 5 business days.
- Fix or mitigation timeline communicated after triage. Critical issues are
  prioritized; lower-severity issues may be batched into the next release.

## Scope

In scope:

- The `parser_lineage_analyzer` Python package and its native extension.
- Built wheels and the source distribution published through the project's
  GitHub Releases.
- The CI/CD configuration in `.github/workflows/` insofar as it affects the
  integrity of released artifacts.

Out of scope:

- Vulnerabilities in third-party dependencies that are already tracked
  upstream (please report those to the affected project; we will prioritize
  a patch release once an upstream fix is available, with the urgency
  matching the severity of the underlying issue).
- Denial-of-service caused by intentionally pathological inputs that are not
  parsed in production deployments. Quadratic or exponential blowups on
  realistic configuration files are in scope.

## Coordinated Disclosure

We prefer coordinated disclosure. Once a fix is available, we will publish a
GitHub Security Advisory with credit to the reporter (unless anonymity is
requested) and a CVE if applicable.
