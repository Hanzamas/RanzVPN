# The one-executable check of ONE-1 (#310, ADR-0011 amendment of 2026-10-22): the Go programs ship as
# one executable, ranz, whose subcommands controller and bgp are what the executables ranz-controller
# and ranz-bgp were. So CI (.github/), the WiX packages (*.wxs) and the docs (docs/) build, run and
# name no executable of those two names. The check reads those files for
# - the file name of either executable, with its .exe,
# - the path of a main package for either, under cmd/ (what go build would be given), and
# - a command line that runs either: its name followed by a verb or a flag of the old program.
# What it leaves alone: the Windows service of the Controller is still named ranz-controller (a
# service name, its virtual account and its event source, not an executable), as are the directories
# of its data; the sidecar's log and pipe names keep ranz-bgp. This script and the fixtures of the
# quality gates hold the forbidden text on purpose, so they are not read.
#
# Usage: python one-binary-check.py [--root DIR]    exit status 1 when a file names one
#
# Standard library only.

import argparse
import os
import re
import sys

FORBIDDEN = [
    (re.compile(r'ranz-(?:controller|bgp)\.exe'), 'the file name of an executable that ranz replaces'),
    (re.compile(r'cmd/ranz-(?:controller|bgp)\b'), 'the path of a main package that ranz replaces'),
    (re.compile(r'\branz-(?:controller|bgp) +(?:install|uninstall|reset-admin|backup|restore|-[a-z])'),
     'a command line of a program that ranz replaces'),
]
# The directories read whatever their files are called, and the extensions read anywhere in the tree
SCOPE_DIRS = ['.github', 'docs']
SCOPE_EXTENSIONS = ('.wxs', '.wxi')
SKIPPED = ['.github/scripts/one-binary-check.py', '.github/scripts/quality-gates-test.py']
# Trees that hold no WiX package of ours
SKIPPED_DIRS = {'build', 'node_modules', '3rdparty', 'vcpkg_installed'}


def files(root):
    seen = set()
    for top in SCOPE_DIRS:
        for base, dirs, names in os.walk(os.path.join(root, top)):
            dirs[:] = sorted(d for d in dirs if d != '.git')
            for name in sorted(names):
                seen.add(os.path.join(base, name))
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.') and d not in SKIPPED_DIRS)
        for name in sorted(names):
            if name.endswith(SCOPE_EXTENSIONS):
                seen.add(os.path.join(base, name))
    return sorted(seen)


def check(root):
    skipped = {os.path.normpath(os.path.join(root, s)) for s in SKIPPED}
    problems = []
    for path in files(root):
        if os.path.normpath(path) in skipped:
            continue
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        shown = os.path.relpath(path, root).replace(os.sep, '/')
        for number, line in enumerate(text.splitlines(), 1):
            for pattern, what in FORBIDDEN:
                m = pattern.search(line)
                if m:
                    problems.append('%s:%d: "%s" is %s: the controller and the BGP sidecar are the subcommands '
                                    'controller and bgp of ranz (ONE-1)' % (shown, number, m.group(0), what))
    return problems


def main():
    ap = argparse.ArgumentParser(description='The one-executable check of ONE-1')
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    args = ap.parse_args()
    problems = check(os.path.abspath(args.root))
    for p in problems:
        print('::error::' + p if os.environ.get('GITHUB_ACTIONS') else p)
    if problems:
        print('%d problems: CI, the WiX packages and the docs name no executable of ranz-controller or ranz-bgp' % len(problems))
        return 1
    print('CI, the WiX packages and the docs name no executable of ranz-controller or ranz-bgp: ranz is the one Go executable')
    return 0


if __name__ == '__main__':
    sys.exit(main())
