# The per-module coverage floor of ADR-0040 item 2. A module below its floor in
# .github/quality/coverage-floors.txt fails the job; so does a module that has no floor yet, so a new
# module cannot hide behind the others.
#
# The floors file has one module per line:
#   c   <module> <floor %> <files>     a C module of the new core: the line coverage of llvm-cov over
#                                      <files>, a glob of .c files (src/Core/Noise*.c)
#   go  <package> <floor %>            a Go package (controller/internal/control): the statement
#                                      coverage of go test -coverprofile; generated code (*.pb.go) is
#                                      left out
# Text after '#' is a comment.
#
# Modes:
#   llvm --export FILE [--scope DIR]   FILE is the JSON of llvm-cov export -summary-only. Every .c file
#                                      of DIR (src/Core) must belong to one C module.
#   go --module DIR --profile FILE     FILE is the profile of go test -coverprofile run in the Go module
#                                      DIR (controller, ranz-bgp); every package of DIR in it with
#                                      statements needs a floor.
# The table of modules goes to the job log and to $GITHUB_STEP_SUMMARY. Exit status 1 when a module
# is below its floor, has no floor, or a floor names a module that has no coverage data.
#
# Standard library only.

import argparse
import fnmatch
import json
import os
import posixpath
import re
import sys

FLOORS = '.github/quality/coverage-floors.txt'


def read_floors(path):
    c_modules, go_packages, problems = [], {}, []
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            fields = line.split('#', 1)[0].split()
            if not fields:
                continue
            where = '%s:%d' % (FLOORS, number)
            try:
                if fields[0] == 'c' and len(fields) == 4:
                    c_modules.append({'name': fields[1], 'floor': float(fields[2]), 'glob': fields[3]})
                    continue
                if fields[0] == 'go' and len(fields) == 3:
                    go_packages[fields[1]] = float(fields[2])
                    continue
            except ValueError:
                pass
            problems.append('%s: "%s" is not "c <module> <floor> <files>" or "go <package> <floor>"' % (where, line.strip()))
    return c_modules, go_packages, problems


def report(kind, rows, problems):
    # rows: (module, covered, total, floor or None); prints the table and returns the exit status
    lines = ['| %s module | covered | lines or statements | coverage | floor | |' % kind, '|---|---:|---:|---:|---:|---|']
    for name, covered, total, floor in rows:
        percent = 100.0 * covered / total if total else 0.0
        if floor is None:
            verdict = 'no floor'
            problems.append('%s: %.1f%% covered and no floor in %s: record one' % (name, percent, FLOORS))
        elif percent + 1e-9 < floor:
            verdict = 'below the floor'
            problems.append('%s: %.1f%% covered, below its floor of %.1f%%' % (name, percent, floor))
        else:
            verdict = 'ok'
        lines.append('| %s | %d | %d | %.1f%% | %s | %s |' % (name, covered, total, percent,
                                                                '-' if floor is None else '%.1f%%' % floor, verdict))
    print('\n'.join(lines))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write('### Coverage floor (%s)\n\n%s\n\n' % (kind, '\n'.join(lines)))
    for p in problems:
        print('::error::' + p if os.environ.get('GITHUB_ACTIONS') else p)
    if problems:
        print('%d problems: a module below its coverage floor fails the build (ADR-0040 item 2)' % len(problems))
        return 1
    print('Every %s module is at or above its coverage floor' % kind)
    return 0


def relative(path, root):
    # The path relative to root, with '/': llvm-cov names Windows paths, whatever system reads them
    path = posixpath.normpath(path.strip().replace('\\', '/'))
    prefix = posixpath.normpath(root.replace('\\', '/')).rstrip('/') + '/'
    if path.lower().startswith(prefix.lower()):
        return path[len(prefix):]
    return path


def llvm(args, root):
    c_modules, _, problems = read_floors(os.path.join(root, FLOORS))
    with open(args.export, encoding='utf-8') as f:
        export = json.load(f)
    files = {}
    for data in export.get('data', []):
        for entry in data.get('files', []):
            lines = entry['summary']['lines']
            files[relative(entry['filename'], root)] = (lines['covered'], lines['count'])

    # Every .c file of the scope belongs to one module
    scope = args.scope.rstrip('/')
    for name in sorted(os.listdir(os.path.join(root, scope))):
        path = scope + '/' + name
        if not name.endswith('.c'):
            continue
        owners = [m['name'] for m in c_modules if fnmatch.fnmatchcase(path, m['glob'])]
        if not owners:
            problems.append('%s belongs to no C module of %s: add it to one, or add its module with a floor' % (path, FLOORS))
        elif len(owners) > 1:
            problems.append('%s belongs to %s: one module only' % (path, ', '.join(owners)))

    rows = []
    for m in c_modules:
        covered = total = 0
        matched = [p for p in files if fnmatch.fnmatchcase(p, m['glob'])]
        for p in matched:
            covered += files[p][0]
            total += files[p][1]
        if not matched:
            problems.append('%s: llvm-cov has no file of %s: is the module linked into the program that ran?' % (m['name'], m['glob']))
            continue
        rows.append((m['name'], covered, total, m['floor']))
    return report('C', rows, problems)


_PROFILE_RE = re.compile(r'^(.+\.go):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$')


def go(args, root):
    _, floors, problems = read_floors(os.path.join(root, FLOORS))
    module_dir = args.module.strip('/')
    module_path = None
    with open(os.path.join(root, module_dir, 'go.mod'), encoding='utf-8') as f:
        for line in f:
            if line.startswith('module '):
                module_path = line.split()[1]
    if not module_path:
        raise SystemExit('%s/go.mod names no module' % module_dir)

    # Each block once, with the highest count any test binary gave it
    blocks = {}
    with open(args.profile, encoding='utf-8') as f:
        for line in f:
            m = _PROFILE_RE.match(line.strip())
            if not m or m.group(1).endswith('.pb.go'):
                continue
            key = m.group(1, 2, 3, 4, 5)
            statements, count = int(m.group(6)), int(m.group(7))
            old = blocks.get(key)
            blocks[key] = (statements, max(count, old[1] if old else 0))

    packages = {}
    for (path, *_), (statements, count) in blocks.items():
        if not path.startswith(module_path + '/'):
            continue
        package = module_dir + '/' + os.path.dirname(path[len(module_path) + 1:])
        package = package.rstrip('/')
        covered, total = packages.get(package, (0, 0))
        packages[package] = (covered + (statements if count > 0 else 0), total + statements)

    rows = []
    for package in sorted(packages):
        covered, total = packages[package]
        if total == 0:
            continue
        rows.append((package, covered, total, floors.get(package)))
    for package in sorted(floors):
        if (package == module_dir or package.startswith(module_dir + '/')) and package not in packages:
            problems.append('%s: a floor in %s and no coverage data: a package that no longer exists?' % (package, FLOORS))
    return report('Go', rows, problems)


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    ap = argparse.ArgumentParser(description='The per-module coverage floor of ADR-0040 item 2')
    sub = ap.add_subparsers(dest='mode', required=True)
    p = sub.add_parser('llvm', parents=[common], help='C modules from llvm-cov export -summary-only')
    p.add_argument('--export', required=True)
    p.add_argument('--scope', default='src/Core')
    p = sub.add_parser('go', parents=[common], help='Go packages from go test -coverprofile')
    p.add_argument('--module', required=True)
    p.add_argument('--profile', required=True)
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    return llvm(args, root) if args.mode == 'llvm' else go(args, root)


if __name__ == '__main__':
    sys.exit(main())
