# Solution: Case Management Onboarding

Turn on automatic case creation for an account or site. Creation rules turn incoming alerts into
cases: a matching alert opens a case with the rule's severity and default tasks, and later alerts
that share the grouping property (the asset, the user, the remote IP) join that case. Analysts then
work one incident instead of a stream of related alerts, and Claude's investigations start from the
case.

This is part of the `sdl-solutions` skill. Playbook:
[`sdl-solutions/references/case-management-onboarding.md`](../../skills/sdl-solutions/references/case-management-onboarding.md).
Rule library: [`sdl-solutions/assets/case_creation_rules.json`](../../skills/sdl-solutions/assets/case_creation_rules.json).
Tools: the Case Management tools in `s1-secops-mcp` (`case_rules`, `case_rule_apply`,
`case_rules_scope`, `case_list`, `case_get`, `case_triage`) and `uam_ingest_alert` for the test.
Reference: [`mgmt-console-api/references/CASE_MANAGEMENT.md`](../../skills/mgmt-console-api/references/CASE_MANAGEMENT.md).

## Run it with one prompt

- *"Set up case creation rules for the Acme account"*
- *"Onboard our site to Case Management with the starter rules, and test it"*

## Starter rules

| Rule | Matches | Case severity | Groups by | Default tasks |
|---|---|---|---|---|
| Critical alerts | alert severity is CRITICAL | Critical | asset, 24 h | confirm with threat intelligence, contain if confirmed, find the initial access vector |
| Ransomware | classification is ransomware | Critical | asset, 24 h | isolate, check mapped and network drives, hunt the hash and storyline elsewhere |
| Credential access | MITRE tactic TA0006 and severity MEDIUM or higher | High | user and asset, 24 h | reset credentials if confirmed, review recent authentications |
| Lateral movement | MITRE tactic TA0008 | High | user, 24 h | map every host reached, check the source host for credential theft |
| Command and control | MITRE tactic TA0011 | High | asset and remote IP, 24 h | enrich remote IPs and domains, block confirmed infrastructure |
| Exfiltration or impact | MITRE tactic TA0010 or TA0040 | Critical | asset, 24 h | scope the affected data or systems, engage incident response |

Every expression was validated on a live console. Rule names carry a prefix so they stay apart from
rules that already exist; existing rules are never changed.

## What happens

1. **Current state.** Claude reads the scope's creation rules and whether the scope inherits them
   from the level above.
2. **Inheritance.** A scope that inherits its rules cannot have rules of its own. Claude explains the
   choice and unlinks only when you say yes: the inherited rules are copied into the scope, which
   keeps its own rules from then on.
3. **Preview.** The rules to deploy, in words, with severity, grouping and tasks. Drop any you do not
   want.
4. **Deploy.** Each rule is validated, created and read back.
5. **End-to-end test.** A temporary rule matching a run tag, a test alert with that tag, and a check
   that the alert opened a case carrying the rule's task. The temporary rule is deleted and the test
   case closed; the test alert and the closed case remain, because cases are not deleted.
6. **Report.** Scope, inheritance before and after, each rule with its id, rank and state, and the
   test result.

## Read-only mode

Reading the rules and the preview work in read-only mode. Deploying rules, unlinking and the test
need write enabled ([read-only.md](../read-only.md)).

## Pair it with a workflow

Creation rules open cases; they do not enrich them. To write a playbook's results to the case
(note, collaboration message, IOCs, status), see the Hyperautomation skill's case write-backs
(`hyperautomation/references/api-integration.md`).
