# The plan of a CI run: which jobs run, and which legs of the matrix jobs. The reusable workflow
# .github/workflows/ci-plan.yml runs this script; windows.yml and ranz.yml read its outputs, and formal.yml
# reads full.
#
# A pull request runs the fast set: the jobs and the legs that check a change before it merges. Every
# other event runs the full set (a push to master or integration, the nightly schedule, workflow_dispatch),
# and so does a pull request that carries the label full-ci or changes a path of SENSITIVE: the code and
# the scripts that only the jobs of the full set test. The full set is every job of windows.yml and
# ranz.yml and both architectures of each matrix job. The legs of the fast set are in MATRICES.
#
# Outputs, one name=value line each, in the file of GITHUB_OUTPUT or on stdout:
#   full                 true or false
#   reason               why, in one line
#   build_matrix         the legs of build_and_test (windows.yml), the JSON of its matrix.platform
#   debug_matrix         the legs of debug (windows.yml)
#   ranz_windows_matrix  the legs of windows (ranz.yml)
#
# Usage: python3 -I ci-plan.py [--event NAME] [--event-file FILE] [--files-from FILE] [--output FILE]
# The defaults are the environment of a workflow run: GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_OUTPUT
# and GITHUB_REPOSITORY. The files that a pull request changes come from the API (gh api, with GH_TOKEN),
# or from --files-from: one path per line, a renamed file as the new path, a tab and the old path. A
# failed API call fails the script, so a plan is never made from a list that it did not read.
#
# Standard library only.

import argparse
import json
import os
import re
import subprocess
import sys

LABEL = 'full-ci'
# The API lists at most this many files of a pull request. One that reaches it may change a path of
# SENSITIVE beyond the list, so it runs the full set.
FILE_LIMIT = 3000

# A pull request that changes one of these paths runs the full set: a pattern at the start of the path
# of the repository, and what it holds. The old path of a renamed file counts too.
SENSITIVE = [
    (r'src/Core/Crypto', 'the crypto module of the new core'),
    (r'src/Core/Noise', 'the Noise session of the new core'),
    (r'src/SeLow/', 'the SeLow driver'),
    (r'\.github/scripts/self-integrity\.ps1$', 'the signing script'),
    (r'\.github/signing/', 'the signing package'),
    (r'\.github/scripts/install\.ps1$', 'the install script'),
    (r'\.github/msi/', 'the MSI package'),
    (r'\.github/scripts/msi-', 'the MSI scripts'),
    (r'docs/first-test\.md$', 'the runbook of the first test'),
    (r'\.github/scripts/first-test\.ps1$', 'the script that proves the runbook'),
    (r'tests/formal/', 'the formal model of the handshake'),
    (r'\.github/scripts/formal\.py$', 'the script that checks and runs the formal model'),
    (r'\.github/workflows/formal\.yml$', 'the workflow of the formal model'),
    (r'compat/', 'the build of ranz-compat from the frozen Cedar'),
]

X64 = {'ARCHITECTURE': 'x64', 'VCPKG_TRIPLET': 'x64-windows-static', 'RUNNER': 'windows-latest'}
ARM64 = {'ARCHITECTURE': 'arm64', 'VCPKG_TRIPLET': 'arm64-windows-static', 'RUNNER': 'windows-11-arm'}

# The matrix of each job that has legs: its legs in the full set, in order, and the architectures of the
# legs that a pull request runs. A job reads each leg as matrix.platform.
MATRICES = {
    # windows.yml, build_and_test: the build with its tests and gates; arm64 only in the full set
    'build': ([X64, ARM64], ['x64']),
    # windows.yml, debug: the Debug build, a compile check with no tests; a pull request builds arm64
    'debug': ([dict(X64, PRESET='debug'), dict(ARM64, PRESET='debug-arm64')], ['arm64']),
    # ranz.yml, windows: the Go module on Windows; arm64 only in the full set
    'ranz_windows': ([dict(X64, GOARCH='amd64'), dict(ARM64, GOARCH='arm64')], ['x64']),
}


def parse_files(text):
    """The (path, old path or '') of each line of a list of changed files."""
    files = []
    for line in text.splitlines():
        if line.strip():
            path, _, old = line.partition('\t')
            files.append((path, old))
    return files


def api_files(repo, number):
    """The files of a pull request, from the API of GitHub through the gh of the runner."""
    jq = r'.[] | [.filename, (.previous_filename // "")] | join("\t")'
    try:
        p = subprocess.run(['gh', 'api', '--paginate', 'repos/%s/pulls/%d/files' % (repo, number), '--jq', jq],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise SystemExit('cannot run gh to list the files of pull request %d: %s' % (number, e))
    if p.returncode != 0:
        raise SystemExit('gh api could not list the files of pull request %d: %s'
                         % (number, p.stderr.decode('utf-8', 'replace').strip()))
    return parse_files(p.stdout.decode('utf-8'))


def sensitive(files):
    """The first changed path that SENSITIVE holds, with what it holds, or None."""
    for path, old in files:
        for name in (path, old):
            for pattern, what in SENSITIVE:
                if name and re.match(pattern, name):
                    return name, what
    return None


def decide(event, labels, list_files):
    """Whether the run is the full set, and why. list_files returns the changed files of a pull request."""
    if event != 'pull_request':
        return True, 'the event is %s, not a pull request' % event
    if LABEL in [label.lower() for label in labels]:
        return True, 'the pull request carries the label %s' % LABEL
    files = list_files()
    if len(files) >= FILE_LIMIT:
        return True, 'the pull request changes %d files or more, which is all that the API lists' % FILE_LIMIT
    hit = sensitive(files)
    if hit:
        return True, 'the pull request changes %s (%s)' % hit
    return False, 'the pull request has no label %s and changes no sensitive path' % LABEL


def legs(name, full):
    every, pull_request = MATRICES[name]
    return [leg for leg in every if full or leg['ARCHITECTURE'] in pull_request]


def outputs(full, reason):
    values = {'full': 'true' if full else 'false', 'reason': reason}
    for name in MATRICES:
        values[name + '_matrix'] = json.dumps(legs(name, full), separators=(',', ':'))
    return values


def summary(full, reason, values):
    lines = ['### CI plan: the %s set' % ('full' if full else 'fast'), '', 'Why: %s.' % reason, '']
    if not full:
        lines += ['A pull request runs the fast set. The full set runs on a push to integration or master, every night,',
                  'on workflow_dispatch and on a pull request with the label `%s`; add the label to run it here.' % LABEL, '']
    lines += ['| matrix job | legs |', '|---|---|']
    for name in MATRICES:
        lines.append('| %s | %s |' % (name, ', '.join(leg['ARCHITECTURE'] for leg in json.loads(values[name + '_matrix']))))
    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser(description='The plan of a CI run: the fast set or the full set')
    ap.add_argument('--event', default=os.environ.get('GITHUB_EVENT_NAME'))
    ap.add_argument('--event-file', default=os.environ.get('GITHUB_EVENT_PATH'))
    ap.add_argument('--files-from', help='a file with the changed files of a pull request, instead of the API')
    ap.add_argument('--output', default=os.environ.get('GITHUB_OUTPUT'))
    args = ap.parse_args()
    if not args.event:
        ap.error('no event: pass --event, or run it in a workflow')

    labels = []
    list_files = list
    if args.event == 'pull_request':
        if not args.event_file:
            ap.error('a pull request needs --event-file, or GITHUB_EVENT_PATH')
        with open(args.event_file, encoding='utf-8') as f:
            pull_request = json.load(f)['pull_request']
        labels = [label['name'] for label in pull_request.get('labels', [])]
        if args.files_from:
            with open(args.files_from, encoding='utf-8') as f:
                listed = parse_files(f.read())
            list_files = lambda: listed
        else:
            list_files = lambda: api_files(os.environ['GITHUB_REPOSITORY'], pull_request['number'])

    full, reason = decide(args.event, labels, list_files)
    values = outputs(full, reason)
    text = ''.join('%s=%s\n' % item for item in values.items())
    if args.output:
        with open(args.output, 'a', encoding='utf-8', newline='\n') as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    print('CI plan: the %s set, because %s' % ('full' if full else 'fast', reason), file=sys.stderr)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8', newline='\n') as f:
            f.write(summary(full, reason, values))
    return 0


if __name__ == '__main__':
    sys.exit(main())
