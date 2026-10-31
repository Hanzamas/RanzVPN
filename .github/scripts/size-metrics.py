# Size metrics of a build: source lines per directory and the size of each executable.
#
# Informational only (spec #24, ADR-0003 item 13): it prints to the job log and to
# $GITHUB_STEP_SUMMARY and never fails the job on a value. Lines are counted in the C
# sources that git tracks under each directory, third-party code excluded; executables are the
# *.exe files directly in the build directory.

import argparse
import glob
import os
import subprocess
import sys

DIRS = ['src/Cedar', 'src/Mayaqua', 'src/ranz-node', 'src/vpntest', 'src/Core', 'src/coretest']
EXTS = ('.c', '.h')


def count_lines(path):
    with open(path, 'rb') as f:
        data = f.read()
    return data.count(b'\n') + (1 if data and not data.endswith(b'\n') else 0)


def source_files(root, directory):
    out = subprocess.run(['git', 'ls-files', '-z', '--', directory], cwd=root,
                         stdout=subprocess.PIPE, check=True).stdout
    files = []
    for name in out.decode('utf-8', errors='replace').split('\0'):
        if not name or '/3rdparty/' in '/' + name + '/':
            continue
        if name.lower().endswith(EXTS) and os.path.isfile(os.path.join(root, name)):
            files.append(name)
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build-dir', default='build')
    ap.add_argument('--arch', default='', help='job architecture, for the summary heading')
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    build_dir = os.path.join(root, args.build_dir)

    rows = []
    for d in DIRS:
        files = source_files(root, d)
        rows.append((d, len(files), sum(count_lines(os.path.join(root, f)) for f in files)))
    total = ('total', sum(r[1] for r in rows), sum(r[2] for r in rows))

    exes = [(os.path.basename(p), os.path.getsize(p))
            for p in sorted(glob.glob(os.path.join(build_dir, '*.exe')), key=str.lower)]

    print('=== size metrics ===')
    for name, nfiles, nlines in rows + [total]:
        print('%-14s %4d files %8d lines' % (name, nfiles, nlines))
    if exes:
        for name, size in exes:
            print('%-14s %10d bytes' % (name, size))
    else:
        print('no .exe in %s' % build_dir)

    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        heading = 'Size metrics' + (' (%s)' % args.arch if args.arch else '')
        with open(summary, 'a', encoding='utf-8') as f:
            f.write('### %s\n\n| Directory | Files | Lines |\n|---|---:|---:|\n' % heading)
            for name, nfiles, nlines in rows + [total]:
                f.write('| %s | %d | %d |\n' % (name, nfiles, nlines))
            f.write('\n')
            if exes:
                f.write('| Executable | Bytes |\n|---|---:|\n')
                for name, size in exes:
                    f.write('| %s | %d |\n' % (name, size))
            else:
                f.write('No .exe in the build directory.\n')
            f.write('\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
