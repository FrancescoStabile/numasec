# Security

numasec is built for authorized cyber security work. Operators are responsible for ensuring they have explicit permission before testing any system, network, application, or account they do not control.

## Public security reporting

The current public intake path for security reports is GitHub Discussions:

- <https://github.com/FrancescoStabile/numasec/discussions>

When reporting an issue:

- avoid posting exploit details publicly when the issue is sensitive
- include the affected version or commit when known
- describe impact clearly
- provide reproduction steps when safe
- attach logs, screenshots, traces, or artifacts when they help and do not expose sensitive material

If a report requires redaction before public discussion, say so up front in the discussion thread.

## Scope

Reports are most useful when they focus on issues in the numasec product itself, for example:

- authorization or boundary bypasses
- evidence, replay, or reporting integrity failures
- secret exposure or unsafe storage behavior
- remote code execution or privilege escalation paths in the product
- supply chain or release integrity issues

## Legal and operational note

numasec is provided as-is, without warranty. The project and its maintainers are not responsible for misuse of the software.
