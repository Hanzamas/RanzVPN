# The C static analysis gate of ADR-0040 item 3: the findings of clang-tidy or of MSVC /analyze on
# the new core, compared with the findings recorded in a baseline. A finding that the baseline does
# not hold is new and fails the job; a baseline entry that is no longer found is reported, so it can
# be taken out.
#
# A finding is "<file>|<check>|<message>": the file relative to the repository, the check (the
# clang-tidy check name, or the MSVC warning number C6xxx, C26xxx or C28xxx) and the message without
# its line numbers, so that a finding keeps its key when the code around it moves. Only files under
# the --scope directories count.
#
# Usage:
#   python static-findings.py --tool clang-tidy|msvc --log FILE --baseline FILE [--scope DIR]...
#   python static-findings.py --tool clang-tidy|msvc --log FILE --write-baseline FILE [--scope DIR]...
#
# Standard library only.

import argparse
import os
import posixpath
import re
import sys

# path:line:col: warning: message [check]
_CLANG_TIDY_RE = re.compile(r'^(?P<path>.+?):(?P<line>\d+):(?P<col>\d+): (?:warning|error): (?P<msg>.*?) \[(?P<check>[^\]]+)\]\s*$')
# path(line) : warning C6011: message, or path(line,col): warning C6011: message
_MSVC_RE = re.compile(r'^(?P<path>.+?)\((?P<line>\d+)(?:,\d+)?\)\s*:\s*warning (?P<check>C(?:6|26|28)\d{3})\s*:\s*(?P<msg>.*?)\s*$')
# The path lines that /analyze appends to a message: ": Lines: 12, 13, 15"
_MSVC_LINES_RE = re.compile(r'\s*:\s*Lines:\s*[\d,\s]+$')


def relative(path, root):
    # The path relative to root, with '/': the logs are Windows paths, whatever system reads them
    path = posixpath.normpath(path.strip().replace('\\', '/'))
    prefix = posixpath.normpath(root.replace('\\', '/')).rstrip('/') + '/'
    if path.lower().startswith(prefix.lower()):
        return path[len(prefix):]
    return path


def findings(tool, log, root, scopes):
    # key -> the first "path:line" it was found at
    found = {}
    with open(log, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\r\n')
            m = (_CLANG_TIDY_RE if tool == 'clang-tidy' else _MSVC_RE).match(line)
            if not m:
                continue
            path = relative(m.group('path'), root)
            if not any(path == s or path.startswith(s.rstrip('/') + '/') for s in scopes):
                continue
            msg = m.group('msg')
            if tool == 'msvc':
                msg = _MSVC_LINES_RE.sub('', msg)
            key = '%s|%s|%s' % (path, m.group('check'), msg.strip())
            found.setdefault(key, '%s:%s' % (path, m.group('line')))
    return found


def read_baseline(path):
    keys = set()
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if line and not line.startswith('#'):
                keys.add(line)
    return keys


def main():
    ap = argparse.ArgumentParser(description='The C static analysis gate of ADR-0040 item 3')
    ap.add_argument('--tool', required=True, choices=['clang-tidy', 'msvc'])
    ap.add_argument('--log', required=True)
    ap.add_argument('--scope', action='append', default=[])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--baseline')
    group.add_argument('--write-baseline')
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    args = ap.parse_args()
    root = args.root
    scopes = args.scope or ['src/Core']

    found = findings(args.tool, args.log, root, scopes)
    print('%s: %d findings in %s' % (args.tool, len(found), ', '.join(scopes)))

    if args.write_baseline:
        with open(args.write_baseline, 'w', encoding='utf-8', newline='\n') as f:
            f.write(''.join(key + '\n' for key in sorted(found)))
        return 0

    baseline = read_baseline(args.baseline)
    new = sorted(set(found) - baseline)
    gone = sorted(baseline - set(found))
    for key in gone:
        print('No longer found, take it out of %s: %s' % (args.baseline, key))
    for key in new:
        path, check, msg = key.split('|', 2)
        text = '%s: %s [%s], a new finding of %s' % (found[key], msg, check, args.tool)
        print('::error::' + text if os.environ.get('GITHUB_ACTIONS') else text)
    if new:
        print('%d new findings: a new finding of the static analysis fails the build (ADR-0040 item 3)' % len(new))
        return 1
    print('No new %s finding (%d recorded in %s)' % (args.tool, len(baseline), args.baseline))
    return 0


if __name__ == '__main__':
    sys.exit(main())
