# Fixtures for ci-plan.py, the plan of windows.yml and ranz.yml (.github/workflows/ci-plan.yml).
#
# The script runs as a workflow run runs it, on events and changed files made here: every event but a
# pull request is the full set; a pull request is the fast set unless it carries the label full-ci or
# changes a sensitive path; the fast set has the legs of a pull request and the full set both
# architectures of each matrix job; a plan that cannot read the files of a pull request fails. The
# last fixtures read the workflows: each output that windows.yml and ranz.yml use is one that the plan
# makes, and each key of matrix.platform that a matrix job reads is a key of its legs.
#
# Usage: python -I ci-plan-test.py

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
failures = []


def check(name, ok, detail=''):
    if ok:
        print('ok  ', name)
    else:
        failures.append('%s%s' % (name, ': ' + detail if detail else ''))
        print('FAIL', name)


def write(path, text):
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def plan(event, labels=(), files=(), path=None):
    """Runs ci-plan.py with a made event; returns its exit code, outputs and stderr."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('GITHUB_') and k != 'GH_TOKEN'}
    if path is not None:
        env['PATH'] = path
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'output.txt')
        args = [sys.executable, '-I', os.path.join(HERE, 'ci-plan.py'), '--event', event, '--output', out]
        if event == 'pull_request':
            event_file = os.path.join(tmp, 'event.json')
            write(event_file, json.dumps({'pull_request': {'number': 7, 'labels': [{'name': name} for name in labels]}}))
            args += ['--event-file', event_file]
            if files is not None:
                files_file = os.path.join(tmp, 'files.txt')
                write(files_file, ''.join(line + '\n' for line in files))
                args += ['--files-from', files_file]
            else:
                env['GITHUB_REPOSITORY'] = 'example/example'
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        values = {}
        if os.path.exists(out):
            with open(out, encoding='utf-8') as f:
                values = dict(line.rstrip('\n').split('=', 1) for line in f)
        return p.returncode, values, p.stderr.decode('utf-8', errors='replace')


def archs(values, name):
    return [leg['ARCHITECTURE'] for leg in json.loads(values[name + '_matrix'])]


def expect_set(name, full, event, **kw):
    """The set that a plan makes, with the legs of that set; returns the outputs."""
    code, values, err = plan(event, **kw)
    legs = {'build': ['x64', 'arm64'], 'debug': ['x64', 'arm64'], 'ranz_windows': ['x64', 'arm64']} if full else \
           {'build': ['x64'], 'debug': ['arm64'], 'ranz_windows': ['x64']}
    got = {job: archs(values, job) for job in legs} if 'full' in values else {}
    ok = code == 0 and values.get('full') == ('true' if full else 'false') and got == legs
    check('%s: the %s set' % (name, 'full' if full else 'fast'), ok,
          'exit %d, full=%r (%s), legs %r, want %r\n%s' % (code, values.get('full'), values.get('reason'), got, legs, err))
    return values


def test_events():
    for event in ('push', 'schedule', 'workflow_dispatch'):
        expect_set('the event %s' % event, True, event)
    values = expect_set('a pull request with no label and a doc', False, 'pull_request', files=['docs/ports.md'])
    check('the reason of the fast set', 'full-ci' in values['reason'], values['reason'])


def test_labels():
    expect_set('the label full-ci', True, 'pull_request', labels=['full-ci'], files=['docs/ports.md'])
    expect_set('the label Full-CI', True, 'pull_request', labels=['bug', 'Full-CI'], files=['docs/ports.md'])
    expect_set('other labels', False, 'pull_request', labels=['bug', 'parked'], files=['docs/ports.md'])
    expect_set('a label that only holds the name', False, 'pull_request', labels=['not-full-ci'], files=['docs/ports.md'])


def test_paths():
    for path in ['src/Core/Crypto.c', 'src/Core/CryptoX25519.c', 'src/Core/CryptoInternal.h', 'src/Core/Noise.c',
                 'src/Core/NoiseSession.c', 'src/SeLow/SeLow.c', 'src/SeLow/SeLow.rc', '.github/scripts/self-integrity.ps1',
                 '.github/signing/signing-proof.wxs', '.github/scripts/install.ps1', '.github/msi/ranz.wxs',
                 '.github/msi/standin-ranz.go', '.github/scripts/msi-build.ps1', '.github/scripts/msi-install.ps1',
                 'docs/first-test.md', '.github/scripts/first-test.ps1', 'tests/formal/session-lib.pvl',
                 'tests/formal/session/tls443.pv', '.github/scripts/formal.py', '.github/workflows/formal.yml',
                 'compat/CMakeLists.txt']:
        values = expect_set('a pull request that changes ' + path, True, 'pull_request', files=['docs/ports.md', path])
        check('the reason names ' + path, path in values['reason'], values['reason'])
    for path in ['src/Core/Peer.c', 'src/Core/Transport.c', 'src/Core/CMakeLists.txt', 'src/Cedar/Node.c',
                 'controller/cmd/ranz/install.go', '.github/scripts/fetch-wintun.ps1', '.github/scripts/not-install.ps1',
                 '.github/scripts/not-msi-build.ps1', '.github/scripts/msix.ps1',
                 '.github/workflows/windows.yml', 'docs/src/Core/Crypto.md', 'src/vpntest/cryptotest.c']:
        expect_set('a pull request that changes only ' + path, False, 'pull_request', files=[path])
    expect_set('the old path of a rename', True, 'pull_request', files=['src/Core/Peer.c\tsrc/Core/Crypto.c'])
    expect_set('the new path of a rename', True, 'pull_request', files=['src/Core/Crypto.c\tsrc/Core/Peer.c'])
    expect_set('a rename between paths that are not sensitive', False, 'pull_request', files=['docs/b.md\tdocs/a.md'])
    expect_set('a pull request with no file', False, 'pull_request', files=[])
    many = ['docs/f%d.md' % n for n in range(3000)]
    expect_set('a list that reaches the limit of the API', True, 'pull_request', files=many)
    expect_set('a list below the limit of the API', False, 'pull_request', files=many[:2999])


def test_outputs():
    code, values, err = plan('push')
    check('the outputs of a plan', sorted(values) == ['build_matrix', 'debug_matrix', 'full', 'ranz_windows_matrix', 'reason'],
          repr(sorted(values)))
    check('the debug presets', [leg['PRESET'] for leg in json.loads(values['debug_matrix'])] == ['debug', 'debug-arm64'])
    check('the go architectures', [leg['GOARCH'] for leg in json.loads(values['ranz_windows_matrix'])] == ['amd64', 'arm64'])
    check('the runners', [leg['RUNNER'] for leg in json.loads(values['build_matrix'])] == ['windows-latest', 'windows-11-arm'])
    check('no output has a line break', all('\n' not in v for v in values.values()))


def test_unreadable_files():
    # A pull request with no list of files, no gh on the PATH and no label: the plan fails and writes nothing
    code, values, err = plan('pull_request', files=None, path='')
    check('a plan without the files of the pull request fails', code != 0 and not values, 'exit %d, %r' % (code, values))
    check('and says why', 'gh' in err and 'files' in err, err)
    # The label is enough, so a pull request that has it never asks for the files
    code, values, err = plan('pull_request', labels=['full-ci'], files=None, path='')
    check('the label needs no list of files', code == 0 and values.get('full') == 'true', 'exit %d, %s' % (code, err))


def read(path):
    with open(os.path.join(ROOT, path), encoding='utf-8') as f:
        return f.read()


def job_text(text, job):
    m = re.search(r'^  %s:\n(.*?)(?=^  \S|\Z)' % re.escape(job), text, re.M | re.S)
    return m.group(1) if m else ''


def test_workflows():
    made = set(plan('push')[1])
    shared = read('.github/workflows/ci-plan.yml')
    exposed = set(re.findall(r'value: \$\{\{ jobs\.plan\.outputs\.(\w+) \}\}', shared))
    check('ci-plan.yml exposes every output of the plan', exposed == made, 'exposes %r, the plan makes %r' % (sorted(exposed), sorted(made)))
    legs = {'build_matrix': ('windows.yml', 'build_and_test'), 'debug_matrix': ('windows.yml', 'debug'),
            'ranz_windows_matrix': ('ranz.yml', 'windows')}
    code, values, err = plan('push')
    for workflow in ('windows.yml', 'ranz.yml'):
        text = read('.github/workflows/' + workflow)
        used = set(re.findall(r'needs\.plan\.outputs\.(\w+)', text))
        check('%s reads outputs that the plan makes' % workflow, used and used <= made, 'reads %r' % sorted(used))
        check('%s calls the plan' % workflow, re.search(r'^  plan:\n    uses: \./\.github/workflows/ci-plan\.yml$', text, re.M) is not None)
    for output, (workflow, job) in legs.items():
        text = job_text(read('.github/workflows/' + workflow), job)
        check('%s: %s takes its legs from %s' % (workflow, job, output),
              'fromJSON(needs.plan.outputs.%s)' % output in text and re.search(r'^    needs: .*\bplan\b', text, re.M) is not None)
        keys = set(re.findall(r'matrix\.platform\.(\w+)', text))
        have = set.intersection(*(set(leg) for leg in json.loads(values[output])))
        check('%s: %s reads only keys that every leg has' % (workflow, job), keys <= have, 'reads %r, the legs have %r' % (sorted(keys), sorted(have)))


test_events()
test_labels()
test_paths()
test_outputs()
test_unreadable_files()
test_workflows()

if failures:
    print('\n%d failures:' % len(failures))
    for f in failures:
        print('  ' + f)
    sys.exit(1)
print('\nall fixtures of the CI plan passed')
