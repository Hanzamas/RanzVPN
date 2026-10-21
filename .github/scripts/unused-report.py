# Lists the unused-code warnings of a build log (cmake/RanzWarnings.cmake, RANZ_UNUSED_WARNINGS=ON).
#
# Reads the compiler output that the Build step of .github/workflows/windows.yml saves, keeps the
# warnings (and errors, once they are promoted) of the unused and unreachable family, and writes
# one line per distinct finding: "<path>:<line><TAB><kind><TAB><identifier>". The path is relative
# to the repository root with forward slashes; <kind> is the clang flag without "-W"; <identifier>
# is the first quoted name in the message, or "-" when the message has none (unreachable code).
# A warning in a header repeats once per translation unit; it is listed once.
#
# The list goes to the job log under the line "=== unused-code report ===", to --out, and to
# $GITHUB_STEP_SUMMARY. A missing log is reported and is not an error: the report never fails a build.

import argparse
import os
import re
import sys

# clang-cl prints "file(line,col): warning: ..."; clang prints "file:line:col: warning: ..."
DIAG = re.compile(
    r'^(?P<file>.+?)(?:\((?P<line>\d+)(?:,\d+)?\)\s*|:(?P<line2>\d+):\d+)'
    r':\s*(?P<sev>warning|error):\s*(?P<msg>.*?)\s*\[(?P<flags>[^\]]+)\]\s*$')
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
QUOTED = re.compile(r"'([^']+)'")

# Flags enabled by RANZ_UNUSED_WARNINGS, plus the subgroups they turn on
KINDS = {
    'unused-function', 'unneeded-internal-declaration',
    'unused-variable', 'unused-const-variable', 'unused-but-set-variable',
    'unused-label', 'unreachable-code',
    # printf format checking of Format, FormatArgs, Print and Debug (RANZ_PRINTF_FORMAT, FND-204)
    'format', 'format-extra-args', 'format-insufficient-args', 'format-invalid-specifier',
    'format-security', 'format-zero-length',
}

SUMMARY_MAX_LINES = 3000


def norm_path(path, root, build_dir):
    if not os.path.isabs(path):
        path = os.path.join(build_dir, path)
    path = os.path.normpath(path)
    try:
        rel = os.path.relpath(path, root)
        if not rel.startswith('..'):
            path = rel
    except ValueError:
        pass
    return path.replace('\\', '/')


def parse(text, root, build_dir):
    found = {}
    for raw in text.splitlines():
        m = DIAG.match(ANSI.sub('', raw).strip())
        if not m:
            continue
        kind = None
        for flag in m.group('flags').split(','):
            flag = flag.strip()
            if flag.startswith('-W') and flag[2:] in KINDS:
                kind = flag[2:]
                break
        if kind is None:
            continue
        line = int(m.group('line') or m.group('line2'))
        path = norm_path(m.group('file'), root, build_dir)
        q = QUOTED.search(m.group('msg'))
        ident = q.group(1) if q else '-'
        key = (path.lower(), line, kind, ident)
        if key not in found:
            found[key] = (path, line, kind, ident)
    return [found[k] for k in sorted(found)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True, help='build log (compiler output)')
    ap.add_argument('--out', required=True, help='report file to write')
    ap.add_argument('--arch', default='', help='job architecture, for the summary heading')
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd(),
                    help='repository root (default: $GITHUB_WORKSPACE or the current directory)')
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    print('=== unused-code report ===')
    if not os.path.isfile(args.log):
        print('no build log at %s (the build did not run)' % args.log)
        return 0

    with open(args.log, 'rb') as f:
        text = f.read().decode('utf-8', errors='replace')
    entries = parse(text, root, os.path.dirname(os.path.abspath(args.log)))
    lines = ['%s:%d\t%s\t%s' % e for e in entries]

    counts = {}
    for e in entries:
        counts[e[2]] = counts.get(e[2], 0) + 1
    tally = ', '.join('%s %d' % (k, counts[k]) for k in sorted(counts)) or 'none'

    for line in lines:
        print(line)
    print('=== %d distinct findings (%s) ===' % (len(entries), tally))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        for line in lines:
            f.write(line + '\n')

    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        heading = 'unused-code report' + (' (%s)' % args.arch if args.arch else '')
        name = 'unused-report' + ('-%s' % args.arch if args.arch else '')
        with open(summary, 'a', encoding='utf-8') as f:
            f.write('### %s\n\n' % heading)
            f.write('%d distinct findings: %s. Full list: artifact `%s`.\n\n' % (len(entries), tally, name))
            if lines:
                shown = lines[:SUMMARY_MAX_LINES]
                f.write('<details><summary>findings</summary>\n\n```text\n')
                f.write('\n'.join(shown) + '\n')
                f.write('```\n\n')
                if len(lines) > len(shown):
                    f.write('(first %d of %d shown)\n\n' % (len(shown), len(lines)))
                f.write('</details>\n\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
