# Playbook: Case Management onboarding

Turn on automatic case creation for an account or site from one prompt: decide whether the scope
keeps its own creation rules, deploy a starter set of MITRE-mapped rules with grouping and default
tasks, prove them end to end with a test alert, and leave the scope with only the rules the user
chose.

Tools: the `case_*` tools in s1-secops-mcp. Request shapes, inheritance and expression rules:
`mgmt-console-api/references/CASE_MANAGEMENT.md`. Read it first.

## Invocation prompt (natural language)

> "Set up case creation rules for `<account>`."
>
> "Onboard `<site>` to Case Management with the starter rules, and test it."

## Parameters (ask few; default the rest)

| Parameter | Default | Ask? |
|---|---|---|
| Scope | the account the user names | yes when the token sees more than one account; resolve the name to an id (`GET /web/api/v2.1/accounts?name__contains=`) |
| Own rules or inherited | keep what the scope has now | only when the scope is inheriting (`linked: true`) and the user wants rules of its own |
| Rules | all six in `assets/case_creation_rules.json` | show the list and let the user drop any |
| Prefix | `CM` | no |
| Case scope level | `SITE` | no |
| Enable on deploy | yes, ranked after any existing enabled rules | yes, one word |
| End-to-end test | yes | no |

## Steps

1. **Read the current state.** `case_rules` for the scope (`includeMetadata: true`): `linked`, the
   existing rules (names, rank, enabled) and the properties the console offers. Show the user what is
   there. Existing rules stay untouched.
2. **Inheritance.** When `linked: true`, the scope follows the rules of the level above and none can
   be added here. Explain the choice: stay linked (stop here and point to the rules above) or unlink
   (the inherited rules are copied into the scope and it keeps its own from then on). Unlink only on
   the user's explicit yes: `case_rules_scope` with `linked: false, confirm: true`. Never relink
   without being asked.
3. **Render and preview.** Replace `{{PREFIX}}` in the chosen library entries, skip any whose name
   already exists in the scope, and show the rules (name, condition in words, severity, grouping,
   default tasks). Property values must be in `case_rules` metadata on this console; drop a rule
   whose property or value is missing and say so.
4. **Deploy.** `case_rule_apply` with `action: create` per rule, `enabled` as chosen. The tool
   validates each expression before sending it. Rank: leave new rules after existing enabled ones
   unless the user asks for a different order (`action: rank`).
5. **Test end to end.** Create a temporary rule `<PREFIX> E2E <runTag>` matching
   `ALERT_NAME CONTAINS <runTag>`, enabled, rank 1, with one default task. Ingest one alert whose
   title contains the run tag (`uam_ingest_alert`, with `scope` set to the target site). Poll
   `case_list` with `creationRuleId` every 5 seconds for up to 2 minutes. Pass when the case exists,
   holds the alert (`case_get`) and carries the default task. Then clean up: delete the temporary
   rule, close the test case with `case_triage` (`status: CLOSED, closingReason: "Test"`), and say
   that the test alert and the closed case remain (cases cannot be deleted).
6. **Report.** The scope, `linked` before and after, each rule deployed (id, rank, enabled), the
   end-to-end result with the case's public id, and what was left on the tenant.

## Validation

- Every deployed rule reads back with `case_rules` (`ruleId`) showing the expression, grouping and
  tasks that were sent.
- The test case was opened by the temporary rule (`creationRule.id` on the `case_list` row), holds
  the test alert, and has the rule's default task.

## Gotchas

- Rule writes are refused while the scope is linked; `case_rule_apply` says so and names
  `case_rules_scope`. Unlinking changes how the scope gets its rules from then on: ask first.
- Grouping joins later matching alerts that share the grouping property into the open case for the
  window; an alert already in a case is never moved by a rule.
- Library rules shown by the console may carry expression ids that a write would refuse;
  `case_rule_apply` regenerates ids on update, so edit them through the tool.
- Creation rules open cases; they do not change alert status or verdict. Pair with a Hyperautomation
  workflow (`hyperautomation/references/api-integration.md`, "Case write-backs") to enrich and write
  results to the case.
- Read-only mode refuses every rule write and the scope change; preview still works.
