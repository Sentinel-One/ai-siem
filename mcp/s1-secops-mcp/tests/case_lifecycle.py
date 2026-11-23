#!/usr/bin/env python3
"""Live lifecycle test of the Case Management tools (s1-secops-mcp 1.6.4) against a real console.

Runs the server from this checkout (node index.js) with write enabled and exercises every case tool:
create, list, alerts in and out (including an alert held by another case), update (read-then-write),
triage, notes, tasks, IOCs (created and then deleted), messages, creation rules (create, read,
automatic case from a test alert, update, disable, delete), closing with and without alsoAlerts, and
the read-only refusal. Every step is written to a JSONL file; the run continues after a failed step.

What it leaves on the tenant: four test alerts and three closed test cases named with the run tag
(cases cannot be deleted). Creation rules and IOCs it creates are deleted. It needs a scope whose
creation rules are NOT inherited (case_rules shows linked: false); it does not change inheritance.

Credentials: S1_CONSOLE_URL, S1_CONSOLE_API_TOKEN and S1_HEC_INGEST_URL (for uam_ingest_alert), from the
environment or the OS keychain (S1_PROFILE selects the profile), as for the server.
Arguments: --account <accountId> --site <siteId> --user <console user id to assign>.
Usage: python3 tests/case_lifecycle.py --account 123 --site 456 --user 789
"""
import argparse, json, os, subprocess, sys, time

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ap = argparse.ArgumentParser()
ap.add_argument('--account', required=True)
ap.add_argument('--site', required=True)
ap.add_argument('--user', required=True)
cli = ap.parse_args()
ACCT, SITE, USER = cli.account, cli.site, cli.user


class Mcp:
    def __init__(self, read_only=False):
        env = dict(os.environ)
        env['S1_READ_ONLY'] = 'true' if read_only else 'false'
        self.p = subprocess.Popen(['node', 'index.js'], cwd=SRC, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
        self.n = 0
        self._rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'case-live', 'version': '0'}})
        self._send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def _send(self, m):
        self.p.stdin.write(json.dumps(m) + '\n'); self.p.stdin.flush()

    def _rpc(self, method, params):
        self.n += 1
        want = self.n
        self._send({'jsonrpc': '2.0', 'id': want, 'method': method, 'params': params})
        deadline = time.time() + 300
        while time.time() < deadline:
            line = self.p.stdout.readline()
            if not line:
                raise SystemExit('server exited')
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get('id') == want:
                return m
        raise SystemExit(f'no response for {method}')

    def tools(self):
        return self._rpc('tools/list', {})['result']['tools']

    def call(self, tool, args):
        r = self._rpc('tools/call', {'name': tool, 'arguments': args})
        res = r.get('result') or {}
        text = '\n'.join(c.get('text', '') for c in res.get('content', []) if c.get('type') == 'text')
        err = bool(res.get('isError')) or 'error' in r
        if 'error' in r:
            text = json.dumps(r['error'])
        try:
            data = json.loads(text)
        except ValueError:
            data = text
        return (not err), data

    def close(self):
        try:
            self.p.stdin.close(); self.p.terminate()
        except Exception:
            pass


TAG = os.environ.get('TAG') or time.strftime('CMLIFE-%m%d%H%M%S')
OUT = open(os.environ.get('RESULTS', os.path.join(os.getcwd(), f'case_lifecycle_{TAG}.jsonl')), 'a')
m = Mcp()
summary = []


def step(name, tool, args, expect_ok=True, check=None):
    t = time.time()
    ok, d = m.call(tool, args)
    passed = ok == expect_ok
    note = ''
    if passed and check:
        try:
            r = check(d)
            passed = r is not False
            note = '' if r in (None, True, False) else str(r)
        except Exception as e:
            passed, note = False, f'check raised {e!r}'
    OUT.write(json.dumps({'tag': TAG, 'step': name, 'tool': tool, 'args': args, 'ok': ok, 'passed': passed, 's': round(time.time() - t, 1), 'resp': d}) + '\n'); OUT.flush()
    summary.append((name, passed))
    print(f"{'PASS' if passed else 'FAIL'} {name:48s} {note} {json.dumps(d)[:260] if not passed else ''}")
    return d


def ingest(title):
    ok, d = m.call('uam_ingest_alert', {'scope': f'{ACCT}:{SITE}', 'title': title, 'hostname': f'{TAG.lower()}-host',
                                       'filename': 'cmtest.exe', 'description': 'Case tools live test; safe to ignore'})
    return ok


def find_alert(title, tries=30):
    for _ in range(tries):
        ok, d = m.call('uam_list_alerts', {'searchText': title, 'scopeIds': [ACCT], 'first': 5})
        if ok:
            for a in d.get('alerts', []):
                if a.get('name') == title:
                    return a['id']
        time.sleep(5)
    return None


print('TAG', TAG)
titles = {k: f'{TAG} {k}' for k in ('a1', 'a2', 'a3', 'a4')}
for k in ('a1', 'a2', 'a3'):
    ingest(titles[k])
ids = {k: find_alert(titles[k]) for k in ('a1', 'a2', 'a3')}
print('alerts', ids)
if not all(ids.values()):
    sys.exit('alerts did not appear')

# Reads
step('case_for_alert: none yet', 'case_for_alert', {'alertId': ids['a1']}, check=lambda d: d['case'] is None)

# Create
c1 = step('case_create c1 (a1, types, assignee)', 'case_create', {'name': f'{TAG} case one', 'alertIds': [ids['a1']], 'severity': 'MEDIUM',
          'caseTypes': ['Investigation', f'  {TAG} custom '], 'assigneeUserId': USER},
          check=lambda d: d['processingState'] == 'READY' and d['case']['alertIds'] == [ids['a1']] and d['scope']['scopeType'] == 'SITE')
C1 = c1.get('caseId') if isinstance(c1, dict) else None
c2 = step('case_create c2 (a3)', 'case_create', {'name': f'{TAG} case two', 'alertIds': [ids['a3']], 'severity': 'LOW'},
          check=lambda d: d['processingState'] == 'READY')
C2 = c2.get('caseId') if isinstance(c2, dict) else None
step('case_create refuses 6 case types', 'case_create', {'name': 'x', 'alertIds': [ids['a2']], 'severity': 'LOW', 'caseTypes': list('abcdef')}, expect_ok=False)

step('case_for_alert: a1 -> c1', 'case_for_alert', {'alertId': ids['a1']}, check=lambda d: d['case']['id'] == C1)
step('case_list by name', 'case_list', {'scopeIds': [ACCT], 'name': TAG, 'first': 10}, check=lambda d: {C1, C2} <= {x['id'] for x in d['cases']})
step('case_list by assignee', 'case_list', {'scopeIds': [ACCT], 'assigneeUserId': USER, 'first': 10}, check=lambda d: C1 in {x['id'] for x in d['cases']})
step('case_list by case type', 'case_list', {'scopeIds': [ACCT], 'caseTypes': ['Investigation'], 'first': 50}, check=lambda d: C1 in {x['id'] for x in d['cases']})

# Alerts
step('case_alerts add a2 -> added', 'case_alerts', {'action': 'add', 'caseId': C1, 'alertIds': [ids['a2']]}, check=lambda d: d['added'] == [ids['a2']])
step('case_alerts add a3 (in c2) -> notAdded', 'case_alerts', {'action': 'add', 'caseId': C1, 'alertIds': [ids['a3']]},
     check=lambda d: d['added'] == [] and d['notAdded'][0]['inCase']['id'] == C2)

# Update
step('case_update rename + types, assignee kept', 'case_update', {'caseId': C1, 'name': f'{TAG} case one renamed', 'caseTypes': ['Incident', f'{TAG} custom']},
     check=lambda d: d['after']['assignee'] and d['after']['assignee']['id'] == USER and d['after']['name'].endswith('renamed'))
step('case_update unassign', 'case_update', {'caseId': C1, 'unassign': True}, check=lambda d: d['after']['assignee'] is None)
step('case_update status RESOLVED + verdict', 'case_update', {'caseId': C1, 'status': 'RESOLVED', 'analystVerdict': 'TRUE_POSITIVE_BENIGN'},
     check=lambda d: d['after']['status'] == 'RESOLVED')
step('case_update refuses CLOSED', 'case_update', {'caseId': C1, 'status': 'CLOSED'}, expect_ok=False)

# Triage
step('case_triage c1+c2 IN_PROGRESS HIGH verdict assign', 'case_triage', {'caseIds': [C1, C2], 'status': 'IN_PROGRESS', 'severity': 'HIGH',
     'analystVerdict': 'TRUE_POSITIVE_MALWARE', 'assigneeUserId': USER},
     check=lambda d: all(c['after']['status'] == 'IN_PROGRESS' and c['after']['severity'] == 'HIGH' for c in d['cases']) and 'alerts' not in d)

# Notes, tasks, messages
note = f'{TAG} finding: VT 0/94 on 203.0.113.9 (documentation range, no reputation data).\n\nNext: <check> host & "proxy" logs.'
step('case_add_note (special chars, paragraphs)', 'case_add_note', {'caseId': C1, 'note': note}, check=lambda d: d['noteId'])
t = step('case_task create', 'case_task', {'action': 'create', 'caseId': C1, 'name': f'{TAG} collect triage package', 'assigneeUserId': USER, 'dueDate': '2026-12-15'},
         check=lambda d: d['task']['status'] == 'TO_DO')
TID = t['task']['id'] if isinstance(t, dict) and t.get('task') else None
step('case_task update DONE (keeps name, due)', 'case_task', {'action': 'update', 'caseId': C1, 'taskId': TID, 'status': 'DONE'},
     check=lambda d: d['after']['status'] == 'DONE' and d['after']['name'] == d['before']['name'] and str(d['after'].get('dueDate', ''))[:10] == '2026-12-15')
t2 = step('case_task create DONE', 'case_task', {'action': 'create', 'caseId': C1, 'name': f'{TAG} temp', 'status': 'DONE'}, check=lambda d: d['task']['status'] == 'DONE')
step('case_task delete', 'case_task', {'action': 'delete', 'taskId': t2['task']['id'] if isinstance(t2, dict) and t2.get('task') else 'x'}, check=lambda d: d['deleted'])
msg = step('case_post_message', 'case_post_message', {'caseId': C1, 'message': f'{TAG}: containment done, 1 host isolated'}, check=lambda d: d['messageId'])
step('case_post_message reply', 'case_post_message', {'caseId': C1, 'message': f'{TAG}: ack', 'parentId': msg.get('messageId') if isinstance(msg, dict) else None}, check=lambda d: d['messageId'])

# IOCs
iocs = step('case_iocs link createMissing', 'case_iocs', {'action': 'link', 'caseId': C1, 'createMissing': True, 'validDays': 2,
            'iocs': [{'type': 'IPV4', 'value': '203.0.113.29'}, {'type': 'DNS', 'value': f'{TAG.lower()}.example'}]},
            check=lambda d: len(d['created']) == 2 and len(d['caseIocs']) >= 2)
created = [x['ioCId'] for x in iocs.get('created', [])] if isinstance(iocs, dict) else []
step('case_iocs link refuses missing id without createMissing', 'case_iocs', {'action': 'link', 'caseId': C1, 'iocs': [{'type': 'IPV4', 'value': '203.0.113.30'}]}, expect_ok=False)
if created:
    step('case_iocs relink (idempotent)', 'case_iocs', {'action': 'link', 'caseId': C1, 'iocs': [{'ioCId': created[0], 'type': 'IPV4', 'value': '203.0.113.29'}]})
    step('case_iocs unlink one', 'case_iocs', {'action': 'unlink', 'caseId': C1, 'ioCIds': [created[1]]}, check=lambda d: all(i['ioCId'] != created[1] for i in d['remaining']))

# Full read
step('case_get with alerts', 'case_get', {'caseId': C1, 'includeAlerts': True},
     check=lambda d: len(d['case']['alertIds']) == 2 and len(d['alerts']) == 2 and d['notes'] and d['tasks'] and d['messages'] and d['iocs'])

step('case_alerts remove a2', 'case_alerts', {'action': 'remove', 'caseId': C1, 'alertIds': [ids['a2']]}, check=lambda d: d['removed'] == [ids['a2']])

# Rules
step('case_rules list (unlinked)', 'case_rules', {'scopeIds': [ACCT]}, check=lambda d: d['linked'] is False)
step('case_rules_scope needs confirm', 'case_rules_scope', {'linked': False, 'confirm': False, 'scopeIds': [ACCT]}, expect_ok=False)
step('case_rules_scope already unlinked -> no change', 'case_rules_scope', {'linked': False, 'confirm': True, 'scopeIds': [ACCT]}, check=lambda d: d['changed'] is False)
step('case_rule_apply bad expression refused', 'case_rule_apply', {'action': 'create', 'scopeIds': [ACCT], 'name': f'{TAG} bad', 'severity': 'LOW',
     'expression': {'conditions': [{'property': 'ALERT_SEVERITY', 'operation': 'CONTAINS', 'value': 'x'}]}}, expect_ok=False)
r = step('case_rule_apply create (enabled, rank 1)', 'case_rule_apply', {'action': 'create', 'scopeIds': [ACCT], 'name': f'{TAG} rule', 'severity': 'HIGH',
         'enabled': True, 'rank': 1, 'caseScopeLevel': 'SITE', 'defaultTasks': [f'{TAG} isolate asset', f'{TAG} find patient zero'],
         'grouping': {'properties': ['ASSET_NAME'], 'windowMinutes': 60},
         'expression': {'match': 'all', 'conditions': [{'property': 'ALERT_NAME', 'operation': 'CONTAINS', 'value': f'{TAG} a4'}]}},
         check=lambda d: d['rule']['enabled'] and len(d['rule']['defaultTasks']) == 2)
RID = r.get('ruleId') if isinstance(r, dict) else None
step('case_rules get rule', 'case_rules', {'scopeIds': [ACCT], 'ruleId': RID}, check=lambda d: d['rule']['name'] == f'{TAG} rule')
ingest(titles['a4'])
a4 = find_alert(titles['a4'])
auto = None
for _ in range(24):
    ok, d = m.call('case_list', {'scopeIds': [ACCT], 'creationRuleId': RID, 'first': 5})
    if ok and d['cases']:
        auto = d['cases'][0]; break
    time.sleep(5)
summary.append(('auto case from rule', bool(auto)))
print(f"{'PASS' if auto else 'FAIL'} auto case from rule {auto['name'] if auto else ''}")
AUTO = auto['id'] if auto else None
if AUTO:
    step('auto case has rule tasks + alert', 'case_get', {'caseId': AUTO}, check=lambda d: a4 in d['case']['alertIds'] and len(d['tasks']) == 2)
step('case_rule_apply update severity (grouping kept)', 'case_rule_apply', {'action': 'update', 'scopeIds': [ACCT], 'ruleId': RID, 'severity': 'MEDIUM'},
     check=lambda d: d['after']['severity'] == 'MEDIUM' and d['after']['groupingConfig']['autoGroupingEnabled'] and len(d['after']['defaultTasks']) == 2)
step('case_rule_apply disable', 'case_rule_apply', {'action': 'disable', 'scopeIds': [ACCT], 'ruleId': RID}, check=lambda d: d['enabled'] is False)
step('case_rule_apply delete', 'case_rule_apply', {'action': 'delete', 'scopeIds': [ACCT], 'ruleId': RID}, check=lambda d: d['deleted'])

# Close everything; c1 with alsoAlerts
step('case_triage CLOSED needs reason', 'case_triage', {'caseIds': [C1], 'status': 'CLOSED'}, expect_ok=False)
step('case_triage close c1 alsoAlerts', 'case_triage', {'caseIds': [C1], 'status': 'CLOSED', 'closingReason': 'Test', 'closingNote': f'{TAG} case tools live test',
     'analystVerdict': 'FALSE_POSITIVE_BENIGN', 'alsoAlerts': True},
     check=lambda d: d['cases'][0]['after']['status'] == 'CLOSED' and all(x.get('status') in ('applied', 'already_set', 'scheduled') and x.get('verdict') in ('applied', 'already_set', 'scheduled') for x in d['alerts']))
step('alert a1 now RESOLVED', 'uam_get_alert', {'alertId': ids['a1']}, check=lambda d: (d.get('status') or d.get('alert', {}).get('status')) == 'RESOLVED')
others = [x for x in (C2, AUTO) if x]
step('case_triage close c2 + auto (alerts untouched)', 'case_triage', {'caseIds': others, 'status': 'CLOSED', 'closingReason': 'Test', 'closingNote': f'{TAG} live test'},
     check=lambda d: all(c['after']['status'] == 'CLOSED' for c in d['cases']) and 'alerts' not in d)
step('alert a3 still NEW', 'uam_get_alert', {'alertId': ids['a3']}, check=lambda d: (d.get('status') or d.get('alert', {}).get('status')) == 'NEW')
step('case_update on CLOSED needs a status', 'case_update', {'caseId': C2, 'name': 'x'}, expect_ok=False)

# Cleanup: created IOCs
if created:
    ok, d = m.call('s1_api_delete', {'path': '/web/api/v2.1/threat-intelligence/iocs', 'body': {'filter': {'uuids': created, 'accountIds': [ACCT]}}})
    print('delete IOCs', ok, json.dumps(d)[:200])
m.close()

# Read-only refusal
ro = Mcp(read_only=True)
ok, d = ro.call('case_add_note', {'caseId': C1 or 'x', 'note': 'n'})
summary.append(('read-only refuses case_add_note', (not ok) and 'read-only mode' in str(d)))
ok2, d2 = ro.call('case_get', {'caseId': C1})
summary.append(('read-only allows case_get', ok2))
ro.close()
print('read-only refuse:', not ok, '| read allowed:', ok2)

print(f"\n{sum(p for _, p in summary)}/{len(summary)} passed; TAG {TAG}; cases {C1} {C2} {AUTO}")
for n, p in summary:
    if not p:
        print('  FAILED:', n)
