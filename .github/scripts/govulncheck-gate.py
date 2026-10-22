# The govulncheck gate of ADR-0040 item 3: every vulnerability that the code of a Go module calls
# (a finding of govulncheck at the symbol level) fails the job, unless
# .github/quality/govulncheck-accepted.txt accepts it for the version of the module it was found in,
# with the reason:
#   <OSV id> <module>@<version> <reason>
# An accepted entry names the version, so an upgrade of the module brings the finding back to be
# checked again. The vulnerabilities of imported packages or required modules that the code does
# not call are listed and do not fail the job, as govulncheck's own exit status has it.
#
# Usage: python govulncheck-gate.py [--accepted FILE] JSON...
# JSON is the output of govulncheck -format json (a stream of JSON objects).
#
# Standard library only.

import argparse
import json
import os
import sys

ACCEPTED = '.github/quality/govulncheck-accepted.txt'


def messages(path):
    # The JSON objects of a govulncheck -format json stream
    with open(path, encoding='utf-8') as f:
        text = f.read()
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return
        obj, pos = decoder.raw_decode(text, pos)
        yield obj


def read_accepted(path):
    accepted, problems = {}, []
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            fields = line.split(None, 2)
            if len(fields) < 3 or '@' not in fields[1]:
                problems.append('%s:%d: "%s" is not "<OSV id> <module>@<version> <reason>"' % (path, number, line))
                continue
            accepted[(fields[0], fields[1])] = fields[2]
    return accepted, problems


def main():
    ap = argparse.ArgumentParser(description='The govulncheck gate of ADR-0040 item 3')
    ap.add_argument('--accepted', default=os.path.join(os.environ.get('GITHUB_WORKSPACE') or os.getcwd(), ACCEPTED))
    ap.add_argument('json', nargs='+')
    args = ap.parse_args()

    accepted, problems = read_accepted(args.accepted)
    summaries, called, uncalled = {}, {}, set()
    for path in args.json:
        for m in messages(path):
            if 'osv' in m:
                summaries[m['osv']['id']] = m['osv'].get('summary', '')
            finding = m.get('finding')
            if not finding or not finding.get('trace'):
                continue
            top = finding['trace'][0]
            key = (finding['osv'], '%s@%s' % (top.get('module', '?'), top.get('version', '?')))
            if top.get('function'):
                # The first frame is the vulnerable symbol; the last one is the module's own code that
                # reaches it
                last = finding['trace'][-1]
                where = '%s %s' % (last.get('position', {}).get('filename', last.get('package', '')), last.get('function', ''))
                called.setdefault(key, (finding.get('fixed_version', ''), where.strip(), top.get('function')))
            else:
                uncalled.add(key)

    for osv, module in sorted(uncalled - set(called)):
        print('Not called by the code: %s in %s (%s)' % (osv, module, summaries.get(osv, '')))
    for (osv, module), (fixed, where, symbol) in sorted(called.items()):
        reason = accepted.get((osv, module))
        text = '%s in %s: %s; the code reaches %s from %s; fixed in %s' % (
            osv, module, summaries.get(osv, ''), symbol, where or '?', fixed or 'no release yet')
        if reason:
            print('Accepted: %s (%s)' % (text, reason))
        else:
            problems.append(text)
    for key in sorted(set(accepted) - set(called)):
        print('No longer found, take it out of %s: %s %s' % (args.accepted, key[0], key[1]))

    for p in problems:
        print('::error::' + p if os.environ.get('GITHUB_ACTIONS') else p)
    if problems:
        print('%d problems: a vulnerability that the code calls fails the build unless %s accepts it (ADR-0040 item 3)'
              % (len(problems), ACCEPTED))
        return 1
    print('No vulnerability that the code calls, besides the %d accepted ones' % len([k for k in called if k in accepted]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
