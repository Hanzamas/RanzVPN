# Fixtures for fuzz-campaign.py, the fuzz campaign of AUD-3 (#363; .github/workflows/fuzz.yml).
#
# Each subcommand runs on a throwaway tree or input made here. libFuzzer and go are stood in for by two small programs
# that behave as the real ones do in the cases that matter to the campaign: a clean run, a crash, a timeout, a hang, a
# merge that fails, a build that fails, a failing input saved under testdata. So a campaign that reports nothing, loses a
# corpus or runs the wrong targets fails here first, on every pull request (quality.yml).
#
# Usage: python -I fuzz-campaign-test.py

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(HERE, 'fuzz-campaign.py')

# The script is loaded by its path: no __pycache__ in .github/scripts
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('fuzz_campaign', SCRIPT)
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)

failures = []
# The run of a workflow is what the script reads: no summary file, plain messages
for name in ('GITHUB_ACTIONS', 'GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT', 'GITHUB_REPOSITORY_ID'):
    os.environ.pop(name, None)
os.environ['GITHUB_RUN_ID'] = '4242'
os.environ['GITHUB_SHA'] = 'a' * 40


def check(name, ok, detail=''):
    if ok:
        print('ok  ', name)
    else:
        failures.append('%s: %s' % (name, detail))
        print('FAIL', name)


def write(root, path, text, binary=False):
    full = os.path.join(root, *path.split('/'))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    if binary:
        with open(full, 'wb') as f:
            f.write(text)
    else:
        with open(full, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
    return full


def names(directory):
    return sorted(os.listdir(directory)) if os.path.isdir(directory) else []


def silently(function, *args, **kwargs):
    # The script prints a leg's log tail and verdict; the fixtures only read what it returns
    saved = sys.stdout
    sys.stdout = open(os.devnull, 'w')
    try:
        return function(*args, **kwargs)
    finally:
        sys.stdout.close()
        sys.stdout = saved


def run_script(*args):
    p = subprocess.run([sys.executable, '-I', SCRIPT] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       env={k: v for k, v in os.environ.items() if k not in ('GITHUB_ACTIONS', 'GITHUB_STEP_SUMMARY', 'GITHUB_OUTPUT')})
    return p.returncode, p.stdout.decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------------------------------------------------

REGISTRY = ('# a registry\nsrc/Core  XDecode  fuzz_x\nsrc/Core  XOpen  exempt  opens a key by name\n'
            'controller/internal/wire  Decode       FuzzDecode\ncontroller/internal/wire  Reader.Read  FuzzDecode\n'
            'controller/internal/other  Parse  FuzzOther\n')


def plan_tree(root):
    write(root, '.github/quality/fuzz-targets.txt', REGISTRY)
    write(root, 'src/fuzz/fuzz_common.c', '// shared\n')
    write(root, 'src/fuzz/fuzz_x.c', '// fuzz-max-len: 4096\n')
    write(root, 'src/fuzz/fuzz_y.c', '// fuzz-max-len: 1500\r\n')


def plan_of(root, event, ref='main', minutes='', targets='', branch='main', number=7):
    return fc.plan(root, event, ref, branch, minutes, targets, number)


def test_plan():
    with tempfile.TemporaryDirectory() as root:
        plan_tree(root)
        v = plan_of(root, 'schedule')
        c, go = json.loads(v['c_matrix']), json.loads(v['go_matrix'])
        check('plan: the C legs are the fuzz_*.c files but fuzz_common.c, and the planted fault',
              [leg['id'] for leg in c] == ['fuzz_x', 'fuzz_y', 'fuzz_canary'], c)
        check('plan: the max length of a leg is the one of its source', [leg['max_len'] for leg in c] == [4096, 1500, 64], c)
        check('plan: the Go legs are the Go fuzz tests of the registry, once each, and the planted fault',
              [(leg['package'], leg['test']) for leg in go] ==
              [('./controller/internal/wire', 'FuzzDecode'), ('./controller/internal/other', 'FuzzOther'), ('.', 'FuzzFault')], go)
        check('plan: the id of a Go leg names its package and its test', go[0]['id'] == 'go-controller-internal-wire-FuzzDecode', go[0])
        check('plan: only the planted faults are canaries', [leg['canary'] for leg in c + go] == [False, False, True, False, False, True])
        check('plan: the targets are the legs but the planted faults', v['targets'] == '4', v['targets'])
        check('plan: the nightly run', v['mode'] == 'nightly' and v['seconds'] == str(fc.NIGHTLY_MINUTES * 60) and v['publish'] == 'true'
              and v['upload_name'] == 'fuzz-corpus' and v['seed'] == '7', v)
        check('plan: a job may take the fuzz time and the overhead', v['timeout'] == str(fc.NIGHTLY_MINUTES + fc.OVERHEAD_MINUTES), v['timeout'])

        v = plan_of(root, 'pull_request', ref='12/merge')
        check('plan: a pull request is a smoke run that stores nothing for the next run',
              v['mode'] == 'smoke' and v['seconds'] == str(fc.SMOKE_SECONDS) and v['publish'] == 'false'
              and v['upload_name'] == 'fuzz-smoke' and v['retention_days'] == '1', v)
        check('plan: a smoke run still looks the stored corpus up under the name of the store', v['store_name'] == 'fuzz-corpus')

        v = plan_of(root, 'workflow_dispatch')
        check('plan: a run by hand on the default branch is the campaign of an hour, and stores its corpora',
              v['mode'] == 'campaign' and v['seconds'] == '3600' and v['publish'] == 'true' and v['timeout'] == '90', v)
        v = plan_of(root, 'workflow_dispatch', minutes='5')
        check('plan: the minutes of a run by hand', v['seconds'] == '300' and v['timeout'] == str(5 + fc.OVERHEAD_MINUTES), v)
        v = plan_of(root, 'workflow_dispatch', ref='aud/363', minutes='5')
        check('plan: a run by hand on another branch stores nothing', v['publish'] == 'false' and v['upload_name'] == 'fuzz-smoke', v)

        for bad in ('0', '301', 'x', '-5', '1.5', 'sixty'):
            try:
                plan_of(root, 'workflow_dispatch', minutes=bad)
                check('plan: minutes %r is refused' % bad, False, 'no error')
            except fc.Failure as e:
                check('plan: minutes %r is refused' % bad, 'minutes' in str(e), str(e))
        try:
            plan_of(root, 'push')
            check('plan: an event that the workflow does not run on is refused', False, 'no error')
        except fc.Failure as e:
            check('plan: an event that the workflow does not run on is refused', 'push' in str(e), str(e))

        v = plan_of(root, 'workflow_dispatch', targets='fuzz_x, FuzzOther')
        c, go = json.loads(v['c_matrix']), json.loads(v['go_matrix'])
        check('plan: the words select the targets, and the planted faults stay',
              [leg['id'] for leg in c] == ['fuzz_x', 'fuzz_canary'] and [leg['test'] for leg in go] == ['FuzzOther', 'FuzzFault'], (c, go))
        check('plan: the targets of a selection', v['targets'] == '2', v['targets'])
        v = plan_of(root, 'workflow_dispatch', targets='wire')
        check('plan: a word that no C target has leaves a matrix with its planted fault only',
              [leg['id'] for leg in json.loads(v['c_matrix'])] == ['fuzz_canary'])
        try:
            plan_of(root, 'workflow_dispatch', targets='fuzz_x,nothing')
            check('plan: a word that names no target is refused', False, 'no error')
        except fc.Failure as e:
            check('plan: a word that names no target is refused', 'nothing' in str(e), str(e))

    with tempfile.TemporaryDirectory() as root:
        plan_tree(root)
        write(root, 'src/fuzz/fuzz_z.c', '// no max length\n')
        try:
            plan_of(root, 'schedule')
            check('plan: a C target without a max length is refused', False, 'no error')
        except fc.Failure as e:
            check('plan: a C target without a max length is refused', 'fuzz_z' in str(e), str(e))

    # The real tree: every target that the registry check knows is a leg
    reg = fc.registry()
    v = fc.plan(ROOT, 'schedule', 'master', 'master', '', '', 1)
    c, go = json.loads(v['c_matrix']), json.loads(v['go_matrix'])
    sources = sorted(n[:-2] for n in os.listdir(os.path.join(ROOT, 'src', 'fuzz')) if re.match(r'^fuzz_\w+\.c$', n) and n != 'fuzz_common.c')
    check('plan of the repository: a C leg for each fuzz_<name>.c of src/fuzz', [leg['id'] for leg in c if not leg['canary']] == sources, sources)
    pairs = reg.go_targets(ROOT, '.')
    check('plan of the repository: a Go leg for each Go fuzz test that the registry lists',
          [(leg['package'], leg['test']) for leg in go if not leg['canary']] == pairs)
    ids = [leg['id'] for leg in c + go]
    check('plan of the repository: the ids are unique, and fit the name of an artifact',
          len(ids) == len(set(ids)) and all(re.fullmatch(r'[A-Za-z0-9_.-]+', i) for i in ids), ids)
    check('plan of the repository: every leg of a matrix has the keys that the workflow reads',
          all(set(leg) == set(c[0]) for leg in c) and all(set(leg) == set(go[0]) for leg in go))
    check('plan of the repository: the C matrix needs the fault source and the Go matrix its test file',
          os.path.isfile(os.path.join(HERE, 'fuzz-fault.c')) and os.path.isfile(fc.GO_FAULT))

    # The command line: the outputs go to the file of GITHUB_OUTPUT, one name=value line each
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, 'output')
        code, text = run_script('plan', '--event', 'schedule', '--default-branch', 'master', '--output', out)
        with open(out, encoding='utf-8') as f:
            lines = f.read().splitlines()
        check('plan: the command line writes name=value lines', code == 0 and all(re.fullmatch(r'\w+=.*', line) for line in lines)
              and any(line.startswith('c_matrix=[') for line in lines), '%d: %s' % (code, text))
        code, text = run_script('plan', '--event', 'workflow_dispatch', '--ref-name', 'master', '--default-branch', 'master', '--minutes', '0')
        check('plan: the command line fails on a bad input and says why', code == 1 and 'minutes' in text, '%d: %s' % (code, text))


# ---------------------------------------------------------------------------------------------------------------------
# store-find
# ---------------------------------------------------------------------------------------------------------------------

def artifact(number, created, branch='master', expired=False, repository=1, run=None):
    return {'id': number, 'name': 'fuzz-corpus-fuzz_x', 'expired': expired, 'created_at': created,
            'workflow_run': {'id': run or number * 10, 'head_branch': branch, 'head_repository_id': repository, 'repository_id': 1}}


def test_store_find():
    found = [artifact(1, '2026-10-27T22:00:00Z'), artifact(2, '2026-10-29T22:00:00Z'), artifact(3, '2026-10-28T22:00:00Z')]
    check('store: the newest artifact', fc.pick_artifact(found, 'master')['id'] == 2)
    check('store: a corpus that expired is not restored',
          fc.pick_artifact(found + [artifact(4, '2026-10-30T22:00:00Z', expired=True)], 'master')['id'] == 2)
    check('store: the run of a pull request or of another branch has no say',
          fc.pick_artifact(found + [artifact(5, '2026-10-30T22:00:00Z', branch='aud/363-nightly-fuzz')], 'master')['id'] == 2)
    check('store: nor the run of a fork that has a branch of the same name',
          fc.pick_artifact(found + [artifact(6, '2026-10-30T22:00:00Z', repository=99)], 'master', 1)['id'] == 2)
    check('store: a run of this repository is taken when its id is known', fc.pick_artifact(found, 'master', 1)['id'] == 2)
    check('store: no artifact, no corpus', fc.pick_artifact([], 'master') is None)
    check('store: only a corpus of another branch, no corpus', fc.pick_artifact([artifact(7, '2026-10-30T22:00:00Z', branch='x')], 'master') is None)

    # More than a page of artifacts: every page is read, and the order of the API does not matter
    pages = []
    asked = []

    def api(path):
        asked.append(path)
        page = int(re.search(r'&page=(\d+)', path).group(1))
        return {'artifacts': pages[page - 1] if page <= len(pages) else []}

    pages[:] = [[artifact(n, '2026-09-%02dT00:00:00Z' % (n % 28 + 1)) for n in range(100)],
                [artifact(n, '2026-10-%02dT00:00:00Z' % (n % 28 + 1)) for n in range(100, 200)],
                [artifact(300, '2026-10-30T00:00:00Z')]]
    listed = fc.list_artifacts('Hanzamas/RanzVPN', 'fuzz-corpus-fuzz_x', api=api)
    check('store: every page of the artifacts is read', len(listed) == 201 and len(asked) == 3, '%d artifacts, %d pages' % (len(listed), len(asked)))
    check('store: the name is in the query and quoted', 'name=fuzz-corpus-fuzz_x&per_page=100' in asked[0], asked[0])
    check('store: the newest of all pages', fc.pick_artifact(listed, 'master')['id'] == 300)

    # The command: a corpus found, none found, and a lookup that fails and fails the leg
    class Args:
        name, repo, branch, output = 'fuzz-corpus-fuzz_x', 'Hanzamas/RanzVPN', 'master', None

    with tempfile.TemporaryDirectory() as tmp:
        Args.output = os.path.join(tmp, 'output')
        original = fc.gh_api
        try:
            fc.gh_api = lambda path: {'artifacts': found}
            silently(fc.cmd_store_find, Args)
            with open(Args.output, encoding='utf-8') as f:
                text = f.read()
            check('store-find: the run and the artifact of the newest corpus', text == 'run_id=20\nartifact_id=2\n', text)
            fc.gh_api = lambda path: {'artifacts': []}
            os.remove(Args.output)
            silently(fc.cmd_store_find, Args)
            with open(Args.output, encoding='utf-8') as f:
                text = f.read()
            check('store-find: no corpus yet gives empty outputs, and no failure', text == 'run_id=\nartifact_id=\n', text)

            def broken(path):
                raise fc.Failure('gh api %s failed: HTTP 502' % path)

            fc.gh_api = broken
            try:
                silently(fc.cmd_store_find, Args)
                check('store-find: a failed lookup fails the leg, so that no small corpus is stored over the large one', False, 'no error')
            except fc.Failure as e:
                check('store-find: a failed lookup fails the leg, so that no small corpus is stored over the large one', '502' in str(e), str(e))
        finally:
            fc.gh_api = original

    class Fake:
        def __init__(self, code, out, err=b''):
            self.returncode, self.stdout, self.stderr = code, out, err

    check('gh: the JSON of the API', fc.gh_api('x', run=lambda *a, **k: Fake(0, b'{"artifacts": []}')) == {'artifacts': []})
    try:
        fc.gh_api('repos/x', run=lambda *a, **k: Fake(1, b'', b'HTTP 403'))
        check('gh: an error of the API is a failure', False, 'no error')
    except fc.Failure as e:
        check('gh: an error of the API is a failure', '403' in str(e), str(e))

    def missing(*a, **k):
        raise FileNotFoundError('gh')

    try:
        fc.gh_api('repos/x', run=missing)
        check('gh: no gh is a failure', False, 'no error')
    except fc.Failure as e:
        check('gh: no gh is a failure', 'gh' in str(e), str(e))


# ---------------------------------------------------------------------------------------------------------------------
# c-run: libFuzzer stood in for by a program that takes its command line
# ---------------------------------------------------------------------------------------------------------------------

FAKE_FUZZER = r'''
import hashlib, os, sys, time

args = sys.argv[1:]
flags = {a.split('=', 1)[0]: (a.split('=', 1)[1] if '=' in a else '') for a in args if a.startswith('-')}
dirs = [a for a in args if not a.startswith('-')]
mode = os.environ.get('FAKE_MODE', 'clean')
tag = os.environ.get('FAKE_TAG', 'one')
prefix = flags.get('-artifact_prefix', '')


def save(kind, data):
    with open(prefix + kind + '-' + hashlib.sha1(data).hexdigest(), 'wb') as f:
        f.write(data)


if '-merge' in flags:
    # -merge=1 base inputs: the inputs that add coverage go to base. Here only the inputs called new-a-* do.
    if mode == 'mergefail':
        print('MERGE-OUTER: the merge failed')
        sys.exit(1)
    base, source = dirs
    for name in sorted(os.listdir(source)):
        if name.startswith('new-a') and not os.path.exists(os.path.join(base, name)):
            with open(os.path.join(source, name), 'rb') as f, open(os.path.join(base, name), 'wb') as g:
                g.write(f.read())
    sys.exit(0)

if '-runs' in flags:
    # The replay
    if mode == 'replaycrash':
        print('==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0001')
        save('crash', b'a stored input')
        sys.exit(1)
    print('INFO: seed corpus: files: %d' % sum(len(os.listdir(d)) for d in dirs))
    print('Done 3 runs in 0 second(s)')
    if mode != 'noverdict':
        print('NO MEMORY LEAKS')
    sys.exit(0)

# The fuzz run: new inputs go to the first directory
for name, data in (('new-a-' + tag, b'new a'), ('junk-' + tag, b'junk')):
    with open(os.path.join(dirs[0], name), 'wb') as f:
        f.write(data)
if mode == 'hang':
    time.sleep(60)
if mode == 'crash':
    print('==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x0002')
    save('crash', b'FUZZ')
    sys.exit(1)
if mode == 'timeout':
    print('==1==ERROR: libFuzzer: timeout after 25 seconds')
    save('timeout', b'slow')
    sys.exit(70)
if mode == 'slow':
    save('slow-unit', b'a slow one')
print('stat::number_of_executed_units: 1000')
print('stat::new_units_added: 2')
print('Done 1000 runs in 1 second(s)')
if mode != 'leaky':
    print('NO MEMORY LEAKS')
'''


class CRun:
    """One c-run in a throwaway directory: the code, the manifest, the files of the store and of the findings"""

    def __init__(self, mode='clean', canary=False, tag='one', store=None, seconds=1, grace=60, exe=None, tmp=None):
        self.tmp = tmp or tempfile.mkdtemp(prefix='fuzz-campaign-test-')
        self.root = os.path.join(self.tmp, 'repo')
        self.build = os.path.join(self.tmp, 'build')
        self.store = store or os.path.join(self.tmp, 'store')
        self.findings = os.path.join(self.tmp, 'findings')
        write(self.root, 'src/fuzz/corpus/fuzz_x/seed.bin', 'seed')
        fake = write(self.tmp, 'fake_fuzzer.py', FAKE_FUZZER)
        leg = {'kind': 'c', 'id': 'fuzz_canary' if canary else 'fuzz_x', 'name': 'fuzz_canary' if canary else 'fuzz_x', 'max_len': 4096,
               'canary': canary}
        os.environ['FAKE_MODE'], os.environ['FAKE_TAG'] = mode, tag
        self.code = silently(fc.run_c, leg, self.build, seconds, 5, 'smoke', self.store, self.findings,
                             exe=exe or [sys.executable, fake], root=self.root, grace=grace)
        with open(os.path.join(self.store, 'manifest.json'), encoding='utf-8') as f:
            self.manifest = json.load(f)
        self.last = self.manifest['last']
        self.inputs = names(os.path.join(self.store, 'inputs'))


def test_c_run():
    r = CRun()
    check('c-run: a clean run exits 0', r.code == 0 and r.last['result'] == 'clean' and not r.last['findings'], (r.code, r.last))
    check('c-run: the statistics are the ones of libFuzzer', r.last['executions'] == 1000 and r.last['new_units'] == 2
          and r.last['requested_seconds'] == 1 and r.last['seed'] == 5 and r.last['run_id'] == '4242', r.last)
    check('c-run: the merge keeps the inputs that add coverage, and only those', r.inputs == ['new-a-one'], r.inputs)
    check('c-run: the manifest counts the runs, the seconds and the stored inputs',
          r.manifest['runs'] == 1 and r.manifest['files'] == 1 and r.manifest['bytes'] == 5 and r.manifest['id'] == 'fuzz_x'
          and r.manifest['total_seconds'] == r.last['seconds'], r.manifest)
    check('c-run: a clean run saves no finding', not os.path.exists(r.findings))
    check('c-run: the seeds of the repository are left as they are', names(os.path.join(r.root, 'src/fuzz/corpus/fuzz_x')) == ['seed.bin'])

    # The next night restores the store: the corpus grows, and the runs add up
    r2 = CRun(tag='two', store=r.store, tmp=r.tmp)
    check('c-run: the next run keeps what the first found and adds its own',
          r2.code == 0 and r2.inputs == ['new-a-one', 'new-a-two'] and r2.manifest['runs'] == 2, (r2.code, r2.inputs, r2.manifest))
    check('c-run: the seconds of the runs add up', r2.manifest['total_seconds'] >= r.manifest['total_seconds'], (r.manifest, r2.manifest))

    r = CRun(mode='crash')
    check('c-run: a crash fails the leg', r.code == 1 and r.last['result'] == 'finding' and 'AddressSanitizer' in r.last['message'], (r.code, r.last))
    check('c-run: the finding names the input that libFuzzer saved',
          len(r.last['findings']) == 1 and r.last['findings'][0]['kind'] == 'crash'
          and re.fullmatch(r'fuzz_x-crash-[0-9a-f]{40}', r.last['findings'][0]['file']), r.last['findings'])
    check('c-run: the input and the logs are saved for the artifact',
          r.last['findings'][0]['file'] in names(r.findings) and 'findings.json' in names(r.findings)
          and 'fuzz_x-fuzz.log' in names(r.findings), names(r.findings))
    check('c-run: what the run found before the crash is kept', r.inputs == ['new-a-one'], r.inputs)
    with open(os.path.join(r.findings, 'findings.json'), encoding='utf-8') as f:
        info = json.load(f)
    check('c-run: findings.json says what regress needs', info['kind'] == 'c' and info['target'] == 'fuzz_x'
          and info['files'] == [r.last['findings'][0]['file']], info)

    r = CRun(mode='timeout')
    check('c-run: a timeout fails the leg', r.code == 1 and r.last['result'] == 'finding' and r.last['findings'][0]['kind'] == 'timeout'
          and 'libFuzzer error' in r.last['message'], (r.code, r.last))

    r = CRun(mode='hang', seconds=1, grace=2)
    check('c-run: a process that does not end is a hang, and fails the leg',
          r.code == 1 and r.last['result'] == 'finding' and 'hang' in r.last['message'], (r.code, r.last))

    r = CRun(mode='noverdict')
    check('c-run: a replay that does not end with the verdict of Mayaqua fails the leg',
          r.code == 1 and r.last['result'] == 'finding' and 'NO MEMORY LEAKS' in r.last['message'] and r.last['seconds'] == 0, (r.code, r.last))

    r = CRun(mode='leaky')
    check('c-run: a leak that does not repeat at exit is a warning, as run_fuzzers.ps1 has it',
          r.code == 0 and r.last['result'] == 'clean' and any('leaked memory' in w for w in r.last['warnings']), (r.code, r.last))

    r = CRun(mode='slow')
    check('c-run: a slow unit is a warning, not a finding',
          r.code == 0 and r.last['result'] == 'clean' and not r.last['findings'] and any('slow-unit' in w for w in r.last['warnings']), (r.code, r.last))

    # A stored input that crashes this build: found by the replay, before any fuzzing, and the store stays as it was
    tmp = tempfile.mkdtemp(prefix='fuzz-campaign-test-')
    store = os.path.join(tmp, 'store')
    write(store, 'inputs/old-1', 'old')
    r = CRun(mode='replaycrash', store=store, tmp=tmp)
    check('c-run: a stored input that crashes the build is a finding of the replay',
          r.code == 1 and r.last['result'] == 'finding' and r.last['message'].startswith('replay:') and r.last['seconds'] == 0, (r.code, r.last))
    check('c-run: and the store is left as it was', r.inputs == ['old-1'], r.inputs)

    r = CRun(mode='mergefail')
    check('c-run: a merge that fails fails the leg, as an error of the campaign and not a finding',
          r.code == 1 and r.last['result'] == 'error' and 'merge' in r.last['message'], (r.code, r.last))
    check('c-run: and the store keeps what the run found, unmerged', r.inputs == ['junk-one', 'new-a-one'], r.inputs)

    r = CRun(exe=[os.path.join(tempfile.gettempdir(), 'no-such-fuzzer-exe')])
    check('c-run: a fuzzer that cannot be started fails the leg', r.code == 1 and r.last['result'] == 'error' and 'cannot run' in r.last['message'], r.last)

    # The planted fault: reported, it passes; not reported, it fails
    r = CRun(mode='crash', canary=True)
    check('c-run: the planted fault, found, passes the leg', r.code == 0 and r.last['result'] == 'finding' and r.last['findings'], (r.code, r.last))
    with open(os.path.join(r.build, 'fuzz-work', 'fuzz_canary', 'seeds', 'seed'), 'rb') as f:
        check('c-run: the planted fault starts from its seed, one byte away from the input', f.read() == fc.CANARY_SEED)
    r = CRun(mode='clean', canary=True)
    check('c-run: the planted fault, not found, fails the leg', r.code == 1 and r.last['result'] == 'clean', (r.code, r.last))
    r = CRun(mode='noverdict', canary=True)
    check('c-run: the planted fault needs no verdict of Mayaqua', r.code == 1 and 'NO MEMORY LEAKS' not in r.last['message'], (r.code, r.last))

    # The words that make a run a finding are the ones of run_fuzzers.ps1
    with open(os.path.join(ROOT, 'src', 'fuzz', 'run_fuzzers.ps1'), encoding='utf-8') as f:
        ps1 = f.read()
    problems = re.search(r'function Get-Problems\(.*?\n}\n', ps1, re.S)
    check('c-run: run_fuzzers.ps1 has its Get-Problems', problems is not None)
    body = problems.group(0) if problems else ''
    for needle, what in fc.C_PATTERNS:
        check('c-run: Get-Problems of run_fuzzers.ps1 tests for %r too' % needle, "-match '%s'" % needle in body, needle)
    for m in re.finditer(r"-match '([^']+)'", body):
        check('c-run: %r of Get-Problems is a pattern of the campaign' % m.group(1),
              any(re.search(m.group(1), needle) for needle, _ in fc.C_PATTERNS), m.group(1))


# ---------------------------------------------------------------------------------------------------------------------
# go-run: go stood in for by a program that answers go env, go list and go test -fuzz
# ---------------------------------------------------------------------------------------------------------------------

FAKE_GO = r'''
import os, sys, time

args = sys.argv[1:]
root = os.environ['FAKE_ROOT']
mode = os.environ.get('FAKE_MODE', 'clean')
tag = os.environ.get('FAKE_TAG', 'one')

if args[:2] == ['env', 'GOCACHE']:
    print(os.path.join(root, 'gocache'))
elif args[0] == 'list':
    print('example.com/m/pkg' if args[2] == '{{.ImportPath}}' else os.path.join(root, 'm', 'pkg'))
elif args[0] == 'test':
    name = args[args.index('-fuzz') + 1].strip('^$')
    cache = os.path.join(root, 'gocache', 'fuzz', 'example.com/m/pkg', name)
    os.makedirs(cache, exist_ok=True)
    if mode == 'hang':
        time.sleep(60)
    if mode == 'buildfail':
        print('# example.com/m/pkg\nundefined: x\nFAIL\texample.com/m/pkg [build failed]')
        sys.exit(1)
    with open(os.path.join(cache, 'input-' + tag), 'w') as f:
        f.write('go test fuzz v1\n[]byte("x")\n')
    print('fuzz: elapsed: 3s, execs: 1234 (411/sec), new interesting: 2 (total: 5)')
    print('fuzz: elapsed: 6s, execs: 5678 (420/sec), new interesting: 3 (total: 6)')
    if mode == 'fail':
        directory = os.path.join(root, 'm', 'pkg', 'testdata', 'fuzz', name)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, 'deadbeef'), 'w') as f:
            f.write('go test fuzz v1\n[]byte("FUZZ")\n')
        print('--- FAIL: %s (0.01s)\n    panic: planted\n    Failing input written to testdata/fuzz/%s/deadbeef' % (name, name))
        sys.exit(1)
    if mode == 'failquietly':
        print('FAIL')
        sys.exit(1)
    print('PASS')
else:
    sys.exit(2)
'''


class GoRun:
    def __init__(self, mode='clean', canary=False, tag='one', store=None, seconds=1, grace=60, tmp=None):
        self.tmp = tmp or tempfile.mkdtemp(prefix='fuzz-campaign-test-')
        self.store = store or os.path.join(self.tmp, 'store')
        self.findings = os.path.join(self.tmp, 'findings')
        self.repo = os.path.join(self.tmp, 'm')
        os.makedirs(self.repo, exist_ok=True)
        fake = write(self.tmp, 'fake_go.py', FAKE_GO)
        leg = {'kind': 'go', 'id': 'go-pkg-FuzzX', 'package': './pkg', 'test': 'FuzzX', 'canary': canary}
        os.environ['FAKE_MODE'], os.environ['FAKE_TAG'], os.environ['FAKE_ROOT'] = mode, tag, self.tmp
        self.code = silently(fc.run_go, leg, seconds, 5, 'smoke', self.store, self.findings, go=[sys.executable, fake], root=self.repo,
                             grace=grace)
        with open(os.path.join(self.store, 'manifest.json'), encoding='utf-8') as f:
            self.manifest = json.load(f)
        self.last = self.manifest['last']
        self.inputs = names(os.path.join(self.store, 'inputs'))


def test_go_run():
    os.makedirs(os.path.join(tempfile.gettempdir(), 'fuzz-logs'), exist_ok=True)
    r = GoRun()
    check('go-run: a clean run exits 0', r.code == 0 and r.last['result'] == 'clean' and not r.last['findings'], (r.code, r.last))
    check('go-run: the statistics are the last ones that the engine printed', r.last['executions'] == 5678 and r.last['new_units'] == 3, r.last)
    check('go-run: the corpus of the engine is what the store keeps', r.inputs == ['input-one'] and r.manifest['files'] == 1, r.inputs)
    check('go-run: the manifest counts the run', r.manifest['runs'] == 1 and r.manifest['kind'] == 'go' and r.manifest['id'] == 'go-pkg-FuzzX', r.manifest)

    # The next night: the stored inputs go into the cache of the engine before the run, so that it starts from them
    r2 = GoRun(tag='two', store=r.store, tmp=r.tmp)
    check('go-run: the next run restores the corpus, and grows it', r2.code == 0 and r2.inputs == ['input-one', 'input-two']
          and r2.manifest['runs'] == 2, (r2.code, r2.inputs, r2.manifest))

    r = GoRun(mode='fail')
    check('go-run: a failing input fails the leg', r.code == 1 and r.last['result'] == 'finding' and r.last['findings'][0]['kind'] == 'crash'
          and r.last['findings'][0]['file'] == 'deadbeef', (r.code, r.last))
    saved = os.path.join(r.findings, 'pkg', 'testdata', 'fuzz', 'FuzzX', 'deadbeef')
    check('go-run: the failing input is saved under the path that go test replays it from', os.path.isfile(saved), names(r.findings))
    check('go-run: the log is saved with it', 'go-pkg-FuzzX.log' in names(r.findings), names(r.findings))
    with open(os.path.join(r.findings, 'findings.json'), encoding='utf-8') as f:
        info = json.load(f)
    check('go-run: findings.json says what regress needs', info['kind'] == 'go' and info['files'] == ['pkg/testdata/fuzz/FuzzX/deadbeef'], info)
    check('go-run: the corpus found before the failure is kept', r.inputs == ['input-one'], r.inputs)

    r = GoRun(mode='failquietly')
    check('go-run: a failure with no saved input is still a finding', r.code == 1 and r.last['result'] == 'finding' and not r.last['findings'], (r.code, r.last))

    r = GoRun(mode='hang', seconds=1, grace=2)
    check('go-run: a go test that does not end is a hang, and fails the leg',
          r.code == 1 and r.last['result'] == 'finding' and r.last['findings'] == [{'kind': 'hang', 'file': ''}], (r.code, r.last))

    r = GoRun(mode='buildfail')
    check('go-run: a build that fails is an error of the campaign, not a finding',
          r.code == 1 and r.last['result'] == 'error' and 'did not build' in r.last['message'], (r.code, r.last))

    r = GoRun(mode='fail', canary=True)
    check('go-run: the planted fault, found, passes the leg', r.code == 0 and r.last['result'] == 'finding' and r.last['findings'], (r.code, r.last))
    r = GoRun(mode='clean', canary=True)
    check('go-run: the planted fault, not found, fails the leg', r.code == 1 and r.last['result'] == 'clean', (r.code, r.last))
    check('go-run: the module of the planted fault is removed', not [n for n in os.listdir(tempfile.gettempdir()) if n.startswith('fuzz-fault-')],
          os.listdir(tempfile.gettempdir()))

    module = fc.go_canary_module()
    try:
        with open(os.path.join(module, 'go.mod'), encoding='utf-8') as f:
            mod = f.read()
        with open(os.path.join(module, 'fault_test.go'), encoding='utf-8') as f:
            source = f.read()
        check('go-run: the module of the planted fault holds its one test', mod.startswith('module example.com/fuzzfault')
              and 'func FuzzFault(f *testing.F)' in source and 'package fuzzfault' in source, (mod, source[:200]))
    finally:
        import shutil
        shutil.rmtree(module)


# ---------------------------------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------------------------------

def stored(root, leg, result='clean', seconds=900.0, run_id='4242', findings=None, total=900.0, prefix='fuzz-corpus', warnings=()):
    last = {'run_id': run_id, 'sha': 'a' * 40, 'mode': 'nightly', 'seed': 1, 'requested_seconds': 900, 'seconds': seconds,
            'executions': 123456, 'new_units': 7, 'result': result, 'findings': findings or [], 'warnings': list(warnings),
            'message': 'boom' if result != 'clean' else ''}
    manifest = {'version': 1, 'id': leg['id'], 'kind': leg['kind'], 'runs': 3, 'total_seconds': total, 'files': 12, 'bytes': 2048, 'last': last}
    write(root, '%s-%s/manifest.json' % (prefix, leg['id']), json.dumps(manifest))


LEGS = [{'kind': 'c', 'id': 'fuzz_x', 'name': 'fuzz_x', 'max_len': 4096, 'canary': False},
        {'kind': 'c', 'id': 'fuzz_canary', 'name': 'fuzz_canary', 'max_len': 64, 'canary': True},
        {'kind': 'go', 'id': 'go-pkg-FuzzX', 'package': './pkg', 'test': 'FuzzX', 'canary': False},
        {'kind': 'go', 'id': 'go-canary-FuzzFault', 'package': '.', 'test': 'FuzzFault', 'canary': True}]
FOUND = [{'kind': 'crash', 'file': 'fuzz_canary-crash-' + '0' * 40}]


def clean_run(root, **changes):
    stored(root, LEGS[0], **changes)
    stored(root, LEGS[1], result='finding', findings=FOUND, seconds=1.0)
    stored(root, LEGS[2])
    stored(root, LEGS[3], result='finding', findings=FOUND, seconds=1.0)


def verdict(root, **kw):
    rows, problems = fc.evaluate(LEGS, root, kw.get('prefix', 'fuzz-corpus'), kw.get('run_id', '4242'), kw.get('seconds', 900))
    return rows, problems


def test_report():
    with tempfile.TemporaryDirectory() as root:
        clean_run(root)
        rows, problems = verdict(root)
        check('report: every leg clean and the planted faults reported is a pass', not problems, problems)
        check('report: the status of each row', [r['status'] for r in rows] == ['clean', 'planted fault reported', 'clean', 'planted fault reported'],
              [r['status'] for r in rows])
        text = fc.report_text(rows, problems, 'nightly', 900)
        check('report: the table has a row for each leg', all(leg['id'] in text for leg in LEGS), text)
        check('report: the hours of fuzzing in all runs are counted for the targets, not for the planted faults',
              'libFuzzer under AddressSanitizer 0 of 1, Go 0 of 1' in text, text)
        check('report: no problems, no list of them', '**' not in text.replace('**problems**', '') and 'problems' not in text, text)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, total=3700.0)
        text = fc.report_text(*verdict(root), 'campaign', 900)
        check('report: a target with an hour in all runs is counted (criterion 1 of AUD-3)', 'libFuzzer under AddressSanitizer 1 of 1' in text, text)
        check('report: the hours of a stored corpus are in its row', '| 1.03 |' in text, text)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root)
        os.remove(os.path.join(root, 'fuzz-corpus-go-pkg-FuzzX', 'manifest.json'))
        rows, problems = verdict(root)
        check('report: a leg with no stored corpus is a problem: it did not finish', len(problems) == 1 and 'go-pkg-FuzzX' in problems[0]
              and rows[2]['status'] == 'no corpus stored', problems)
        check('report: a leg that did not finish has a row all the same', 'go-pkg-FuzzX' in fc.report_text(rows, problems, 'nightly', 900))

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, result='finding', findings=[{'kind': 'crash', 'file': 'fuzz_x-crash-' + '1' * 40}])
        rows, problems = verdict(root)
        check('report: a finding is a problem, with its message', len(problems) == 1 and problems[0].startswith('fuzz_x: finding: boom'), problems)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, result='error')
        check('report: an error of the campaign is a problem too', len(verdict(root)[1]) == 1)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, seconds=60.0)
        rows, problems = verdict(root)
        check('report: a leg that ended early with no finding is a problem', len(problems) == 1 and 'ended early' in problems[0], problems)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, seconds=850.0)
        check('report: a few seconds short of the time is no problem', not verdict(root)[1])

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, run_id='4000')
        rows, problems = verdict(root)
        check('report: the corpus of an older run is not the evidence of this one', len(problems) == 1 and 'run 4000' in problems[0] and rows[0]['status'] == 'stale', problems)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root)
        stored(root, LEGS[1], result='clean', seconds=1.0)
        rows, problems = verdict(root)
        check('report: a planted fault that is not reported is a problem', len(problems) == 1 and 'planted fault' in problems[0]
              and rows[1]['status'] == 'planted fault NOT reported', problems)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root)
        stored(root, LEGS[3], result='finding', findings=[])
        check('report: a planted fault that left no input is not reported either', len(verdict(root)[1]) == 1)

    with tempfile.TemporaryDirectory() as root:
        clean_run(root, prefix='fuzz-smoke', warnings=['slow-unit: fuzz_x-slow-unit-abc'])
        stored(root, LEGS[1], result='finding', findings=FOUND, seconds=1.0, prefix='fuzz-smoke')
        stored(root, LEGS[2], prefix='fuzz-smoke')
        stored(root, LEGS[3], result='finding', findings=FOUND, seconds=1.0, prefix='fuzz-smoke')
        rows, problems = verdict(root, prefix='fuzz-smoke')
        text = fc.report_text(rows, problems, 'smoke', 900)
        check('report: a smoke run reads the artifacts of its own prefix', not problems, problems)
        check('report: the warnings of the legs are listed', 'fuzz_x: slow-unit: fuzz_x-slow-unit-abc' in text, text)

    with tempfile.TemporaryDirectory() as root:
        write(root, 'fuzz-corpus-fuzz_x/manifest.json', '{not json')
        rows, problems = fc.evaluate(LEGS[:1], root, 'fuzz-corpus', '4242', 900)
        check('report: a manifest that is not JSON is a corpus that is not stored', len(problems) == 1 and rows[0]['status'] == 'no corpus stored', problems)

    # The command line: the exit status
    with tempfile.TemporaryDirectory() as root:
        clean_run(root)
        args = ['report', '--stores', root, '--prefix', 'fuzz-corpus', '--run-id', '4242', '--seconds', '900', '--mode', 'nightly',
                '--plan-c', json.dumps(LEGS[:2]), '--plan-go', json.dumps(LEGS[2:])]
        code, text = run_script(*args)
        check('report: the command line exits 0 for a clean run', code == 0 and 'Fuzz campaign: nightly' in text, '%d: %s' % (code, text))
        os.remove(os.path.join(root, 'fuzz-corpus-fuzz_x', 'manifest.json'))
        code, text = run_script(*args)
        check('report: and exits 1 for a leg that stored nothing', code == 1 and 'fuzz_x' in text, '%d: %s' % (code, text))


# ---------------------------------------------------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------------------------------------------------

def test_parsers():
    registry = ('src/Core  XDecode  fuzz_x\nsrc/Core  XParseAll  fuzz_x  via XDecode\n'
                'src/Core  XKeyOpen  exempt  opens a key by name; reads no bytes of a peer\n'
                'src/Cedar  NodeThing  exempt  hands the packet to XDecode (fuzz_x), which parses it\n'
                'src/Cedar  NodeOverlayInput  exempt  a packet of the host (SDN-3 #179, merged before the gate): a fuzz target of its own is still to come\n'
                'controller/internal/wire  Decode  FuzzDecode\n')
    core = ('bool XDecode(const UCHAR *p, UINT size) {\n\treturn true;\n}\n'
            'bool XParseAll(const UCHAR *p, UINT size) {\n\treturn true;\n}\n'
            'bool XKeyOpen(const wchar_t *name) {\n\treturn true;\n}\n')
    cedar = 'bool NodeThing(const UCHAR *p) {\n\treturn true;\n}\nbool NodeOverlayInput(const UCHAR *p) {\n\treturn true;\n}\n'
    tree = {'.github/quality/fuzz-targets.txt': registry, 'src/Core/X.c': core, 'src/Cedar/NodeA.c': cedar,
            'src/fuzz/fuzz_x.c': '// fuzz-max-len: 4096\nXDecode(data, size);\n', 'src/fuzz/fuzz_common.c': '// shared\n',
            'src/fuzz/CMakeLists.txt': 'file(GLOB RANZ_FUZZ_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS '
                                       '"${CMAKE_CURRENT_SOURCE_DIR}/fuzz_*.c")\n',
            'src/fuzz/run_fuzzers.ps1': "param([string[]] $Targets = @())\nGet-ChildItem -Filter 'fuzz_*.c'\n",
            'src/fuzz/corpus/fuzz_x/seed.bin': 'x',
            'controller/internal/wire/wire.go': 'package wire\n\nfunc Decode(b []byte) error { return nil }\n',
            'controller/internal/wire/wire_test.go': 'package wire\n\nimport "testing"\n\nfunc FuzzDecode(f *testing.F) {\n\tDecode(nil)\n}\n'}
    with tempfile.TemporaryDirectory() as root:
        for path, text in tree.items():
            write(root, path, text)
        text, problems = fc.parsers_report(root)
        check('parsers: a registry that the check passes has no problems', not problems, problems)
        check('parsers: the functions with a target, those read through another and the exempt ones are counted',
              '| with a fuzz target of its own (libFuzzer or Go) | 3 |' in text
              and '| exempt: read through the fuzz target of another function | 1 |' in text
              and '| exempt: no parser, with its reason | 1 |' in text, text)
        check('parsers: a parser whose line says that its target is still to come is reported, with the text that follows a "#"',
              '| **without a fuzz target (the line says that one is still to come)** | **1** |' in text
              and '- `NodeOverlayInput` of src/Cedar' in text and 'still to come' in text, text)
        code, out = run_script('parsers', '--root', root)
        check('parsers: the command passes while every parser has a line', code == 0 and 'NodeOverlayInput' in out, '%d: %s' % (code, out))

        write(root, 'src/Core/Y.c', 'UINT YParseFrame(const UCHAR *p,\n                 UINT size) {\n\treturn 0;\n}\n')
        text, problems = fc.parsers_report(root)
        check('parsers: a parser with no line at all is a problem of the check, and counted',
              len(problems) == 1 and 'YParseFrame looks like a parser' in problems[0] and '| **1** |' in text.splitlines()[-4] + text, (problems, text))
        code, out = run_script('parsers', '--root', root)
        check('parsers: and the command fails on it', code == 1 and 'YParseFrame' in out, '%d: %s' % (code, out))

    # The registry of the repository: the check passes, and the report holds the parsers that still have no target
    text, problems = fc.parsers_report(ROOT)
    check('parsers: the registry of the repository passes the check', not problems, problems)
    check('parsers: and the report counts its lines', re.search(r'with a fuzz target of its own \(libFuzzer or Go\) \| (\d+) \|', text)
          and int(re.search(r'with a fuzz target of its own \(libFuzzer or Go\) \| (\d+) \|', text).group(1)) > 50, text)
    check('parsers: exemptions are classified', fc.classify_exempt('a fuzz target of its own is still to come') == 'pending'
          and fc.classify_exempt('hands it to PolicyInput (fuzz_policy), which parses it') == 'covered'
          and fc.classify_exempt('which nodecontroller.Parse (FuzzParse) makes') == 'covered'
          and fc.classify_exempt('opens a key by its name') == 'not a parser' and fc.classify_exempt('') == 'not a parser')


# ---------------------------------------------------------------------------------------------------------------------
# regress
# ---------------------------------------------------------------------------------------------------------------------

def test_regress():
    sha = 'ab' * 20
    with tempfile.TemporaryDirectory() as tmp:
        findings, root = os.path.join(tmp, 'findings'), os.path.join(tmp, 'repo')
        write(findings, 'fuzz_x-crash-' + sha, b'FUZZ', binary=True)
        write(findings, 'fuzz_x-timeout-' + 'cd' * 20, b'slow', binary=True)
        write(findings, 'findings.json', json.dumps({'id': 'fuzz_x', 'kind': 'c', 'target': 'fuzz_x', 'package': '',
                                                      'files': ['fuzz_x-crash-' + sha, 'fuzz_x-timeout-' + 'cd' * 20]}))
        made = fc.regress(findings, root)
        check('regress: a C input goes to the seeds of its target, named for what it found',
              made == ['src/fuzz/corpus/fuzz_x/regress-crash-' + sha[:12], 'src/fuzz/corpus/fuzz_x/regress-timeout-' + 'cd' * 6], made)
        with open(os.path.join(root, *made[0].split('/')), 'rb') as f:
            check('regress: the bytes are the ones of the finding', f.read() == b'FUZZ')

    with tempfile.TemporaryDirectory() as tmp:
        findings, root = os.path.join(tmp, 'findings'), os.path.join(tmp, 'repo')
        path = 'controller/internal/wire/testdata/fuzz/FuzzDecode/deadbeef'
        write(findings, path, 'go test fuzz v1\n[]byte("FUZZ")\n')
        write(findings, 'findings.json', json.dumps({'id': 'go-controller-internal-wire-FuzzDecode', 'kind': 'go', 'target': 'FuzzDecode',
                                                      'package': './controller/internal/wire', 'files': [path]}))
        check('regress: a Go input goes to testdata/fuzz of its package, where go test replays it', fc.regress(findings, root) == [path]
              and os.path.isfile(os.path.join(root, *path.split('/'))))
        code, text = run_script('regress', '--findings', findings, '--root', root)
        check('regress: the command says what to do', code == 0 and 'commit these files with the fix' in text, '%d: %s' % (code, text))

    with tempfile.TemporaryDirectory() as tmp:
        try:
            fc.regress(tmp, tmp)
            check('regress: a directory with no findings.json is refused', False, 'no error')
        except fc.Failure as e:
            check('regress: a directory with no findings.json is refused', 'findings.json' in str(e), str(e))
        write(tmp, 'findings.json', json.dumps({'id': 'x', 'kind': 'c', 'target': 'fuzz_x', 'files': ['not-a-finding']}))
        write(tmp, 'not-a-finding', 'x')
        try:
            fc.regress(tmp, tmp)
            check('regress: a file that libFuzzer did not save is refused', False, 'no error')
        except fc.Failure as e:
            check('regress: a file that libFuzzer did not save is refused', 'not a file that libFuzzer saved' in str(e), str(e))


# ---------------------------------------------------------------------------------------------------------------------
# the workflow
# ---------------------------------------------------------------------------------------------------------------------

def read(path):
    with open(os.path.join(ROOT, path), encoding='utf-8') as f:
        return f.read()


def job_text(text, job):
    m = re.search(r'^  %s:\n(.*?)(?=^  \S|\Z)' % re.escape(job), text, re.M | re.S)
    return m.group(1) if m else ''


def test_workflow():
    workflow = read('.github/workflows/fuzz.yml')
    made = set(fc.plan(ROOT, 'schedule', 'master', 'master', '', '', 1))
    used = set(re.findall(r'needs\.plan\.outputs\.(\w+)', workflow))
    check('workflow: fuzz.yml reads outputs that the plan makes', used and used <= made, 'reads %r, the plan makes %r' % (sorted(used), sorted(made)))
    # reason, targets and publish are for the job summary of the plan: upload_name and retention_days carry what publish means
    check('workflow: and the plan makes no output that nothing reads', made - used <= {'reason', 'targets', 'publish'}, sorted(made - used))
    v = fc.plan(ROOT, 'schedule', 'master', 'master', '', '', 1)
    for job, matrix in (('fuzz_c', 'c_matrix'), ('fuzz_go', 'go_matrix')):
        text = job_text(workflow, job)
        check('workflow: %s takes its legs from %s' % (job, matrix), 'fromJSON(needs.plan.outputs.%s)' % matrix in text)
        keys = set(re.findall(r'matrix\.target\.(\w+)', text))
        have = set.intersection(*(set(leg) for leg in json.loads(v[matrix])))
        check('workflow: %s reads only the keys that every leg has' % job, keys and keys <= have, 'reads %r, the legs have %r' % (sorted(keys), sorted(have)))
    # The steps, not the comments: a line of the workflow that is not a comment and runs the script
    steps = '\n'.join(line for line in workflow.splitlines() if not line.lstrip().startswith('#'))
    commands = set(re.findall(r'python3? (?:-I )?\.github/scripts/fuzz-campaign\.py ([a-z-]+)', steps))
    check('workflow: every step runs a subcommand of the script', commands and all(
        run_script(c, '--help')[0] == 0 for c in commands), sorted(commands))
    check('workflow: and every subcommand but regress, which a developer runs, has a step',
          commands == {'plan', 'store-find', 'c-run', 'go-run', 'report', 'parsers'}, sorted(commands))

    ranz = re.search(r"GO_VERSION: '([^']+)'", read('.github/workflows/ranz.yml')).group(1)
    ours = re.search(r"GO_VERSION: '([^']+)'", workflow)
    check('workflow: the Go of the campaign is the Go of ranz.yml', ours is not None and ours.group(1) == ranz, (ours and ours.group(1), ranz))

    # Every script that fuzz.yml runs starts a run of it on a pull request, and no run of windows.yml
    paths = re.search(r'pull_request:\n(?:.*\n)*?    paths:\n((?:    - .*\n)+)', workflow)
    listed = re.findall(r"- '([^']+)'", paths.group(1)) if paths else []
    for path in ('.github/workflows/fuzz.yml', '.github/scripts/fuzz-campaign.py', '.github/scripts/fuzz-fault.c',
                 '.github/scripts/fuzz-fault_test.go'):
        check('workflow: a pull request that changes %s runs fuzz.yml' % path, path in listed, listed)
    windows = read('.github/workflows/windows.yml')
    for path in ('.github/workflows/fuzz.yml', '.github/scripts/fuzz-campaign.py', '.github/scripts/fuzz-campaign-test.py',
                 '.github/scripts/fuzz-fault.c', '.github/scripts/fuzz-fault_test.go'):
        check('workflow: a pull request that changes only %s does not run windows.yml' % path, "- '!%s'" % path in windows)

    check('workflow: the schedule is one a night, and no other run than a pull request, a schedule or a dispatch starts it',
          re.search(r'^  schedule:\n  - cron: ', workflow, re.M) and re.search(r'^  workflow_dispatch:', workflow, re.M)
          and not re.search(r'^  push:', workflow, re.M))


test_plan()
test_store_find()
test_c_run()
test_go_run()
test_report()
test_parsers()
test_regress()
test_workflow()

if failures:
    print()
    print('%d fixtures failed:' % len(failures))
    for f in failures:
        print(' -', f)
    sys.exit(1)
print('All fuzz campaign fixtures passed')
