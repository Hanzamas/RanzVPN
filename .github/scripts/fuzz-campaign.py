# The fuzz campaign (AUD-3, #363; ADR-0040 item 1): every fuzz target of .github/quality/fuzz-targets.txt runs for a long time
# against a corpus that is stored between runs and grows, and the same targets run every night. .github/workflows/fuzz.yml
# runs one subcommand in each of its steps; the fixtures of every subcommand are in fuzz-campaign-test.py (quality.yml).
#
# A leg of the campaign is one target:
# - a libFuzzer target of src/fuzz (c-run, on Windows, under AddressSanitizer, built as the fuzz-asan job of windows.yml
#   builds them). It replays the stored corpus and the seeds of src/fuzz/corpus, fuzzes for the given seconds with the stored
#   corpus as the directory that new inputs go to, and merges what it found into the smallest set that adds coverage to the
#   seeds (libFuzzer -merge=1), which is what the store keeps;
# - a Go fuzz test (go-run, on Linux): go test -fuzz with the stored corpus put in the fuzz cache of the Go build cache,
#   and what that cache holds after the run kept. Go is memory safe and the module builds with no cgo, so the checks of the
#   Go engine (a panic, a failed test, a process that dies) are the checks of a Go leg.
# A finding (a crash, a timeout, an out-of-memory, a leak of Mayaqua objects, a panic, a hang) fails the leg and is saved as a
# file that "regress" turns into a regression test: a file of src/fuzz/corpus/<target>, which every full run replays, or
# a file of testdata/fuzz/<test>, which go test replays. Each leg keeps its corpus and its statistics in one directory, the
# store, which fuzz.yml uploads as the artifact fuzz-corpus-<id> and the next run restores:
#   manifest.json   the runs and the seconds of fuzzing that fed the corpus, and the report of the last run
#   inputs/         the corpus (for a C target only what the seeds do not cover)
# Each kind of target has a planted fault next to it, a leg that must be reported as a finding (fuzz-fault.c,
# fuzz-fault_test.go), so a campaign that reports nothing cannot pass for one that found nothing.
#
# Subcommands:
#   plan        what a run fuzzes and for how long: the legs of the two matrices, the seconds, the seed, whether the corpora are
#               stored. The outputs go to $GITHUB_OUTPUT, one name=value line each.
#   store-find  the newest stored corpus of one target: an artifact of a run on the default branch of this repository
#   c-run       one libFuzzer target: replay, fuzz, merge
#   go-run      one Go fuzz test
#   report      the verdict of a run from what each leg stored, as a table in $GITHUB_STEP_SUMMARY; exit status 1 when a
#               leg found something, did not finish, ran short or did not store its corpus
#   parsers     the parsers of the registry and which of them has no fuzz target of its own (criterion 4 of AUD-3)
#   regress     what a developer runs on the artifact fuzz-findings-<id> of a failed leg: each finding goes where it is replayed
#
# Standard library only.

import argparse
import importlib.util
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# What each kind of run fuzzes for. A run of a pull request that changes the machinery is a smoke run: every leg proves that
# it works. The schedule is the nightly run. A run by hand is the campaign of AUD-3, an hour for every target by default.
SMOKE_SECONDS = 20
NIGHTLY_MINUTES = 15
CAMPAIGN_MINUTES = 60
MAX_MINUTES = 300
# The job timeout is the fuzz time and this many minutes more: the setup, the replay of the corpus and the merge
OVERHEAD_MINUTES = 30
# A process that runs this many seconds past its fuzz time is taken for hung
HANG_GRACE = 15 * 60
# The seconds of fuzzing in total that the criterion of AUD-3 asks of every target
ONE_HOUR = 3600

# The artifacts of the stores: fuzz-corpus-<id> of a run that stores its corpora for the next one, fuzz-smoke-<id> of a run
# that does not (a pull request, a run by hand on another branch)
STORE_NAME = 'fuzz-corpus'
SMOKE_STORE_NAME = 'fuzz-smoke'
RETENTION_DAYS = 60

# The planted faults: one leg of each matrix, which must end in a finding
C_CANARY = {'kind': 'c', 'id': 'fuzz_canary', 'name': 'fuzz_canary', 'max_len': 64, 'canary': True}
GO_CANARY = {'kind': 'go', 'id': 'go-canary-FuzzFault', 'package': '.', 'test': 'FuzzFault', 'canary': True}
# The seed of the planted fault: one byte away from the input that triggers it
CANARY_SEED = b'FUZY'
GO_FAULT = os.path.join(HERE, 'fuzz-fault_test.go')

# The text of a libFuzzer or Mayaqua run that makes it a finding: the same as Get-Problems of src/fuzz/run_fuzzers.ps1
C_PATTERNS = (
    ('ERROR: AddressSanitizer', 'an AddressSanitizer report'),
    ('ERROR: libFuzzer', 'a libFuzzer error (a crash, a timeout or an out-of-memory)'),
    ('Fatal Error: ', 'a Mayaqua fatal error (AbortExitEx)'),
    ('==RANZ FUZZ== Mayaqua objects leaked', 'an input that leaked Mayaqua objects'),
)
# libFuzzer saves the input of each finding under -artifact_prefix as <prefix><kind>-<sha1>
ARTIFACT_RE = re.compile(r'^(?P<target>.+?)-(?P<kind>crash|timeout|oom|leak|slow-unit)-(?P<hash>[0-9a-f]{8,})$')


class Failure(Exception):
    """A problem of the campaign itself, not a finding of a fuzz target"""


def registry():
    # The registry script has a dash in its name: load it by its path, and leave no __pycache__ in .github/scripts
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('fuzz_registry', os.path.join(HERE, 'fuzz-registry.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_outputs(values, path):
    text = ''.join('%s=%s\n' % item for item in values.items())
    if path:
        with open(path, 'a', encoding='utf-8', newline='\n') as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def write_summary(text):
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path, 'a', encoding='utf-8', newline='\n') as f:
            f.write(text + '\n')


def annotate(level, message):
    # A line that the job log shows as an error or a warning when it runs in a workflow
    if os.environ.get('GITHUB_ACTIONS'):
        print('::%s::%s' % (level, message))
    else:
        print('%s: %s' % (level, message))


# ---------------------------------------------------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------------------------------------------------

def c_legs(root, reg):
    # Every fuzz_<name>.c of src/fuzz but fuzz_common.c is a target (src/fuzz/CMakeLists.txt, run_fuzzers.ps1)
    directory = os.path.join(root, reg.FUZZ_DIR)
    legs = []
    for name in sorted(n[:-2] for n in os.listdir(directory) if re.match(r'^fuzz_\w+\.c$', n)):
        if name == 'fuzz_common':
            continue
        max_len = reg.max_len_of(os.path.join(directory, name + '.c'))
        if max_len is None:
            raise Failure('%s/%s.c has no line "// fuzz-max-len: <bytes>"' % (reg.FUZZ_DIR, name))
        legs.append({'kind': 'c', 'id': name, 'name': name, 'max_len': max_len, 'canary': False})
    return legs


def go_legs(root, reg):
    # The Go fuzz tests that the registry lists, as ranz.yml runs them
    legs = []
    for package, test in reg.go_targets(root, '.'):
        legs.append({'kind': 'go', 'id': 'go-%s-%s' % (package[2:].replace('/', '-'), test), 'package': package,
                     'test': test, 'canary': False})
    return legs


def words_of(text):
    return [w for w in re.split(r'[,\s]+', text or '') if w]


def select(legs, words):
    # The legs whose id has one of the words in it; a word that names no leg is a typo, not an empty run
    for word in words:
        if not any(word in leg['id'] for leg in legs):
            raise Failure('no fuzz target has "%s" in its id, for example %s' % (word, ', '.join(leg['id'] for leg in legs[:3])))
    return [leg for leg in legs if any(word in leg['id'] for word in words)]


def decide(event, ref_name, default_branch, minutes_text):
    """The mode of the run, the seconds that each target is fuzzed and whether the corpora are stored for the next run"""
    if event == 'pull_request':
        return 'smoke', SMOKE_SECONDS, False
    if event == 'schedule':
        return 'nightly', NIGHTLY_MINUTES * 60, True
    if event == 'workflow_dispatch':
        text = (minutes_text or '').strip() or str(CAMPAIGN_MINUTES)
        if not re.fullmatch(r'\d+', text) or not 1 <= int(text) <= MAX_MINUTES:
            raise Failure('minutes is "%s": a whole number from 1 to %d' % (text, MAX_MINUTES))
        # A run on another branch holds a corpus that the default branch has not reviewed: it stores none for later runs
        return 'campaign', int(text) * 60, ref_name == default_branch
    raise Failure('the event is "%s": the workflow runs on pull_request, schedule and workflow_dispatch' % event)


def plan(root, event, ref_name, default_branch, minutes_text, targets_text, run_number):
    reg = registry()
    mode, seconds, publish = decide(event, ref_name, default_branch, minutes_text)
    c, go = c_legs(root, reg), go_legs(root, reg)
    words = words_of(targets_text)
    if words:
        chosen = select(c + go, words)
        c = [leg for leg in chosen if leg['kind'] == 'c']
        go = [leg for leg in chosen if leg['kind'] == 'go']
    targets = len(c) + len(go)
    # Each matrix has its planted fault, so that neither is ever empty
    c, go = c + [dict(C_CANARY)], go + [dict(GO_CANARY)]
    reason = {'smoke': 'a pull request that changes the machinery: %d s for each target' % seconds,
              'nightly': 'the schedule: %d minutes for each target' % (seconds // 60),
              'campaign': 'a run by hand: %d minutes for each target' % (seconds // 60)}[mode]
    return {
        'mode': mode,
        'reason': reason,
        'seconds': str(seconds),
        'seed': str(run_number),
        'publish': 'true' if publish else 'false',
        'store_name': STORE_NAME,
        'upload_name': STORE_NAME if publish else SMOKE_STORE_NAME,
        'retention_days': str(RETENTION_DAYS if publish else 1),
        'timeout': str(math.ceil(seconds / 60) + OVERHEAD_MINUTES),
        'targets': str(targets),
        'c_matrix': json.dumps(c, separators=(',', ':')),
        'go_matrix': json.dumps(go, separators=(',', ':')),
    }


def plan_summary(values):
    c, go = json.loads(values['c_matrix']), json.loads(values['go_matrix'])
    return '\n'.join([
        '### Fuzz plan: %s' % values['mode'], '',
        'Why: %s.' % values['reason'], '',
        '| | |', '|---|---|',
        '| targets | %s (%d libFuzzer under AddressSanitizer, %d Go), and a planted fault of each kind |'
        % (values['targets'], len(c) - 1, len(go) - 1),
        '| time for each target | %s s |' % values['seconds'],
        '| corpora stored for the next run | %s (artifacts %s-<target>) |' % (values['publish'], values['upload_name']), ''])


def cmd_plan(args):
    env = os.environ
    values = plan(args.root, args.event or env.get('GITHUB_EVENT_NAME', ''), args.ref_name or env.get('GITHUB_REF_NAME', ''),
                  args.default_branch or env.get('DEFAULT_BRANCH', ''), args.minutes, args.targets,
                  int(env.get('GITHUB_RUN_NUMBER') or 1))
    write_outputs(values, args.output or env.get('GITHUB_OUTPUT'))
    write_summary(plan_summary(values))
    print('Fuzz plan: %s' % values['reason'], file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------------------------------------------------
# store-find
# ---------------------------------------------------------------------------------------------------------------------

def gh_api(path, run=subprocess.run):
    try:
        p = run(['gh', 'api', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise Failure('cannot run gh to read %s: %s' % (path, e))
    if p.returncode != 0:
        raise Failure('gh api %s failed: %s' % (path, p.stderr.decode('utf-8', 'replace').strip()))
    return json.loads(p.stdout.decode('utf-8'))


def list_artifacts(repo, name, api=None):
    # Every artifact of this name, a page of 100 at a time
    api = api or gh_api
    found = []
    for page in range(1, 11):
        batch = api('repos/%s/actions/artifacts?name=%s&per_page=100&page=%d' % (repo, urllib.parse.quote(name, safe=''), page))
        found += batch.get('artifacts', [])
        if len(batch.get('artifacts', [])) < 100:
            break
    return found


def pick_artifact(artifacts, branch, repository_id=None):
    """The newest artifact that has not expired and that a run on the branch of this repository made: the run of a pull
    request, of a fork or of another branch has no say in the corpus that the next campaign starts from"""
    best = None
    for artifact in artifacts:
        run = artifact.get('workflow_run') or {}
        if artifact.get('expired') or run.get('head_branch') != branch:
            continue
        if repository_id is not None and run.get('head_repository_id') != repository_id:
            continue
        if best is None or artifact.get('created_at', '') > best.get('created_at', ''):
            best = artifact
    return best


def cmd_store_find(args):
    if not args.repo:
        raise Failure('no repository: pass --repo, or run in a workflow')
    repository_id = os.environ.get('GITHUB_REPOSITORY_ID')
    # A failed lookup fails the leg: a leg that went on without the corpus would store a small one over the newest
    artifacts = list_artifacts(args.repo, args.name)
    best = pick_artifact(artifacts, args.branch, int(repository_id) if repository_id else None)
    if best is None:
        print('No stored corpus %s of a run on %s (%d artifacts of that name): the leg starts from the seeds'
              % (args.name, args.branch, len(artifacts)))
        values = {'run_id': '', 'artifact_id': ''}
    else:
        print('Stored corpus %s: artifact %s of run %s, made %s' % (args.name, best['id'], best['workflow_run']['id'], best.get('created_at')))
        values = {'run_id': str(best['workflow_run']['id']), 'artifact_id': str(best['id'])}
    write_outputs(values, args.output or os.environ.get('GITHUB_OUTPUT'))
    return 0


# ---------------------------------------------------------------------------------------------------------------------
# the store and the report of a leg
# ---------------------------------------------------------------------------------------------------------------------

def read_manifest(store):
    try:
        with open(os.path.join(store, 'manifest.json'), encoding='utf-8') as f:
            manifest = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        annotate('warning', 'the manifest of the stored corpus is unreadable (%s): its statistics start again' % e)
        return {}
    return manifest if isinstance(manifest, dict) else {}


def tree_size(directory):
    files, size = 0, 0
    for base, _, names in os.walk(directory):
        for name in names:
            files += 1
            size += os.path.getsize(os.path.join(base, name))
    return files, size


def write_manifest(store, leg, previous, last):
    files, size = tree_size(os.path.join(store, 'inputs'))
    manifest = {
        'version': 1,
        'id': leg['id'],
        'kind': leg['kind'],
        'runs': int(previous.get('runs', 0)) + 1,
        'total_seconds': round(float(previous.get('total_seconds', 0)) + last['seconds'], 1),
        'files': files,
        'bytes': size,
        'last': last,
    }
    with open(os.path.join(store, 'manifest.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write('\n')
    return manifest


def new_last(mode, seed, seconds):
    return {'run_id': os.environ.get('GITHUB_RUN_ID', ''), 'sha': os.environ.get('GITHUB_SHA', ''), 'mode': mode, 'seed': seed,
            'requested_seconds': seconds, 'seconds': 0.0, 'executions': 0, 'new_units': 0, 'result': 'clean', 'findings': [],
            'warnings': [], 'message': ''}


class Result:
    def __init__(self, code, text, timed_out=False):
        self.code, self.text, self.timed_out = code, text, timed_out


def execute(command, log, timeout, cwd=None):
    """Runs a command with its input closed (a leak report would wait for Enter) and its output in the file log"""
    os.makedirs(os.path.dirname(log), exist_ok=True)
    code, timed_out = None, False
    with open(log, 'wb') as f:
        f.write(('> ' + ' '.join(command) + '\n').encode('utf-8'))
        f.flush()
        try:
            code = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT, cwd=cwd,
                                  timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        except OSError as e:
            raise Failure('cannot run %s: %s' % (command[0], e))
    with open(log, 'rb') as f:
        return Result(code, f.read().decode('utf-8', errors='replace'), timed_out)


def capture(command, cwd):
    try:
        p = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failure('cannot run %s: %s' % (' '.join(command), e))
    if p.returncode != 0:
        raise Failure('%s exited with %d: %s' % (' '.join(command), p.returncode, p.stderr.decode('utf-8', 'replace').strip()))
    return p.stdout.decode('utf-8', 'replace').strip()


def tail(text, lines=150):
    return '\n'.join(text.splitlines()[-lines:])


def last_number(pattern, text):
    found = re.findall(pattern, text)
    return int(found[-1]) if found else 0


def replace_tree(directory, source, names):
    # The files names of source are all that directory holds afterwards
    shutil.rmtree(directory, ignore_errors=True)
    os.makedirs(directory)
    for name in names:
        shutil.copy2(os.path.join(source, name), os.path.join(directory, name))


def save_findings(directory, leg, files, logs):
    """files: (path, name) of each input that a finding saved; the logs of the leg go beside them"""
    os.makedirs(directory, exist_ok=True)
    for path, name in files:
        target = os.path.join(directory, *name.split('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(path, target)
    for log in logs:
        if os.path.isfile(log):
            shutil.copy2(log, os.path.join(directory, os.path.basename(log)))
    with open(os.path.join(directory, 'findings.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'id': leg['id'], 'kind': leg['kind'], 'target': leg.get('name') or leg.get('test'),
                   'package': leg.get('package', ''), 'files': [name for _, name in files]}, f, indent=1)
        f.write('\n')


def conclude(last, found, error, failed, saved):
    """Sets the result of a leg from what its steps found: failed is (step, problems) of each step that found something,
    found (kind, file) of each input that was saved, error the problem of the campaign itself"""
    last['findings'] = [{'kind': kind, 'file': name} for kind, name in found]
    if failed:
        last['result'] = 'finding'
        last['message'] = '; '.join('%s: %s' % (step, ', '.join(problems)) for step, problems in failed)
        if error:
            last['warnings'].append(error)
    elif found:
        last['result'] = 'finding'
        last['message'] = 'the fuzzer saved %d inputs' % len(found)
    elif error:
        last['result'] = 'error'
        last['message'] = error


def finish(leg, store, previous, last, findings_dir, saved, logs, shown):
    """Writes the manifest, keeps the inputs of the findings and says how the leg ended. Returns the exit status"""
    write_manifest(store, leg, previous, last)
    if leg['canary']:
        # The planted fault must be found, and the input that found it saved
        ok = last['result'] == 'finding' and bool(saved)
        if not ok:
            annotate('error', '%s: the planted fault was not reported as a finding (%s): the campaign would not report a real one'
                     % (leg['id'], 'no input was saved' if last['result'] == 'finding' else last['result']))
    else:
        ok = last['result'] == 'clean'
        if not ok:
            annotate('error', '%s: %s%s' % (leg['id'], last['result'], ': ' + last['message'] if last['message'] else ''))
    if saved or not ok:
        save_findings(findings_dir, leg, saved, logs)
    if shown is not None:
        print(tail(shown.text))
    print('%s: %s, %.0f s of %d s, %d executions, %d new inputs, %s' % (leg['id'], last['result'], last['seconds'], last['requested_seconds'],
                                                                      last['executions'], last['new_units'], last['message'] or 'no finding'))
    return 0 if ok else 1


# ---------------------------------------------------------------------------------------------------------------------
# c-run
# ---------------------------------------------------------------------------------------------------------------------

def c_problems(result, verdict):
    """What makes a run of a libFuzzer target a finding. verdict: the run must end with Mayaqua's verdict NO MEMORY LEAKS"""
    problems = []
    if result.timed_out:
        problems.append('the process did not end in time (a hang)')
    elif result.code != 0:
        problems.append('exit code %s' % result.code)
    problems += [what for needle, what in C_PATTERNS if needle in result.text]
    if verdict and 'NO MEMORY LEAKS' not in result.text:
        problems.append('no "NO MEMORY LEAKS" verdict')
    return problems


def new_artifacts(directory, target, known):
    """The inputs that libFuzzer saved for this target since the files in known: (path, name, kind)"""
    found = []
    if os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            m = ARTIFACT_RE.match(name)
            if name not in known and m and m.group('target') == target:
                found.append((os.path.join(directory, name), name, m.group('kind')))
    return found


def merge_corpus(exe, common, seeds, inputs, work, log, cwd):
    """libFuzzer -merge=1 into a copy of the seeds: it adds the inputs that reach coverage that the seeds do not, and only
    those, so what the copy gains over the seeds is the smallest set to keep. The store is replaced with it."""
    base = os.path.join(work, 'merge-base')
    shutil.rmtree(base, ignore_errors=True)
    shutil.copytree(seeds, base)
    seed_names = set(os.listdir(base))
    result = execute(exe + common + ['-merge=1', base, inputs], log, 1800, cwd=cwd)
    if result.timed_out or result.code != 0:
        raise Failure('the merge of the corpus %s (log %s)' % ('did not end in time' if result.timed_out else 'exited with %s' % result.code, log))
    kept = sorted(name for name in os.listdir(base) if name not in seed_names)
    replace_tree(inputs, base, kept)
    return len(kept)


def run_c(leg, build_dir, seconds, seed, mode, store, findings_dir, exe=None, root=ROOT, grace=HANG_GRACE):
    target, canary = leg['name'], leg['canary']
    # The fuzzer runs in the build directory, as run_fuzzers.ps1 runs it: every path that it is given must not depend on that
    build_dir, store, findings_dir, root = (os.path.abspath(path) for path in (build_dir, store, findings_dir, root))
    exe = exe or [os.path.join(build_dir, target + '.exe')]
    inputs = os.path.join(store, 'inputs')
    os.makedirs(inputs, exist_ok=True)
    previous = read_manifest(store)
    artifacts = os.path.join(build_dir, 'fuzz-artifacts')
    logs = os.path.join(build_dir, 'fuzz-logs')
    work = os.path.join(build_dir, 'fuzz-work', target)
    os.makedirs(artifacts, exist_ok=True)
    os.makedirs(work, exist_ok=True)
    known = set(os.listdir(artifacts))
    if canary:
        seeds = os.path.join(work, 'seeds')
        os.makedirs(seeds, exist_ok=True)
        with open(os.path.join(seeds, 'seed'), 'wb') as f:
            f.write(CANARY_SEED)
    else:
        seeds = os.path.join(root, 'src', 'fuzz', 'corpus', target)
    common = ['-max_len=%d' % leg['max_len'], '-timeout=25', '-rss_limit_mb=2048', '-artifact_prefix=' + os.path.join(artifacts, target + '-')]
    log = lambda step: os.path.join(logs, '%s-%s.log' % (target, step))
    last = new_last(mode, seed, seconds)
    failed, shown, error = [], None, ''

    try:
        # 1. Replay: the stored corpus and the seeds, once each. A stored input that crashes this build is a finding too
        print('[%s] replay %s and %s' % (target, inputs, seeds))
        result = execute(exe + common + ['-runs=0', inputs, seeds], log('replay'), grace, cwd=build_dir)
        problems = c_problems(result, verdict=not canary)
        if problems:
            failed.append(('replay', problems))
            shown = result
        else:
            # 2. Fuzz: new inputs go to the store, the seeds stay as they are
            print('[%s] fuzz %d s, seed %d' % (target, seconds, seed))
            started = time.monotonic()
            result = execute(exe + common + ['-max_total_time=%d' % seconds, '-seed=%d' % seed, '-print_final_stats=1', inputs, seeds],
                             log('fuzz'), seconds + grace, cwd=build_dir)
            last['seconds'] = round(time.monotonic() - started, 1)
            last['executions'] = last_number(r'stat::number_of_executed_units:\s*(\d+)', result.text)
            last['new_units'] = last_number(r'stat::new_units_added:\s*(\d+)', result.text)
            problems = c_problems(result, verdict=False)
            if problems:
                failed.append(('fuzz', problems))
                shown = result
            elif not canary and 'NO MEMORY LEAKS' not in result.text:
                last['warnings'].append('Mayaqua reported leaked memory at exit (see %s)' % log('fuzz'))
            # 3. Merge, also after a finding: what the run found before it stopped is kept
            print('[%s] merge into the smallest set that adds coverage to the seeds' % target)
            print('[%s] %d inputs kept' % (target, merge_corpus(exe, common, seeds, inputs, work, log('merge'), build_dir)))
    except Failure as e:
        error = str(e)

    saved = new_artifacts(artifacts, target, known)
    last['warnings'] += ['%s: %s' % (kind, name) for path, name, kind in saved if kind == 'slow-unit']
    saved = [item for item in saved if item[2] != 'slow-unit']
    conclude(last, [(kind, name) for path, name, kind in saved], error, failed, saved)
    return finish(leg, store, previous, last, findings_dir, [(path, name) for path, name, kind in saved],
                  [log(step) for step in ('replay', 'fuzz', 'merge')], shown)


def cmd_c_run(args):
    leg = {'kind': 'c', 'id': args.id, 'name': args.target, 'max_len': args.max_len, 'canary': args.canary}
    return run_c(leg, args.build_dir, args.seconds, args.seed, args.mode, args.store, args.findings)


# ---------------------------------------------------------------------------------------------------------------------
# go-run
# ---------------------------------------------------------------------------------------------------------------------

def go_canary_module():
    # The planted fault is the one test file of a module of its own, made here: no go.mod in the tree for the tools to read
    directory = tempfile.mkdtemp(prefix='fuzz-fault-')
    with open(os.path.join(directory, 'go.mod'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('module example.com/fuzzfault\n\ngo 1.21\n')
    shutil.copy2(GO_FAULT, os.path.join(directory, 'fault_test.go'))
    return directory


def replace_tree_from(directory, source):
    if os.path.isdir(source):
        replace_tree(directory, source, sorted(n for n in os.listdir(source) if os.path.isfile(os.path.join(source, n))))


def run_go(leg, seconds, seed, mode, store, findings_dir, go=None, root=ROOT, grace=HANG_GRACE):
    go = go or ['go']
    test, canary = leg['test'], leg['canary']
    store, findings_dir, root = (os.path.abspath(path) for path in (store, findings_dir, root))
    inputs = os.path.join(store, 'inputs')
    os.makedirs(inputs, exist_ok=True)
    previous = read_manifest(store)
    last = new_last(mode, seed, seconds)
    module = go_canary_module() if canary else None
    base = os.path.realpath(module or root)
    cwd, package = (module, '.') if canary else (root, leg['package'])
    log = os.path.join(tempfile.gettempdir(), 'fuzz-logs', '%s.log' % leg['id'])
    failed, saved, shown, error, hung = [], [], None, '', False
    try:
        import_path = capture(go + ['list', '-f', '{{.ImportPath}}', package], cwd)
        package_dir = capture(go + ['list', '-f', '{{.Dir}}', package], cwd)
        # The corpus of the Go engine: $GOCACHE/fuzz/<import path>/<test>. The engine reads it next to the seeds of f.Add and
        # testdata/fuzz/<test>, and adds the inputs that reach new coverage; a failing input goes to testdata/fuzz/<test>
        cache = os.path.join(capture(go + ['env', 'GOCACHE'], cwd), 'fuzz', import_path, test)
        testdata = os.path.join(package_dir, 'testdata', 'fuzz', test)
        known = set(os.listdir(testdata)) if os.path.isdir(testdata) else set()
        os.makedirs(cache, exist_ok=True)
        for name in os.listdir(inputs):
            if not os.path.exists(os.path.join(cache, name)):
                shutil.copy2(os.path.join(inputs, name), os.path.join(cache, name))
        print('[%s] go test -fuzz %s for %d s over %d stored inputs' % (leg['id'], test, seconds, len(os.listdir(inputs))))
        started = time.monotonic()
        # The engine has no timeout for one input: -timeout bounds the whole run, and so does the one of our own
        result = execute(go + ['test', '-run', '^$', '-fuzz', '^%s$' % test, '-fuzztime', '%ds' % seconds, '-timeout',
                               '%dm' % (math.ceil(seconds / 60) + 10), package], log, seconds + grace, cwd=cwd)
        last['seconds'] = round(time.monotonic() - started, 1)
        last['executions'] = last_number(r'execs:\s*(\d+)', result.text)
        last['new_units'] = last_number(r'new interesting:\s*(\d+)', result.text)
        if result.timed_out:
            hung = True
            failed.append(('fuzz', ['go test did not end in time (a hang)']))
            shown = result
        elif result.code != 0:
            if '[build failed]' in result.text or '[setup failed]' in result.text:
                raise Failure('go test did not build: %s' % tail(result.text, 5).replace('\n', ' | '))
            failed.append(('fuzz', ['go test exited with %s' % result.code]))
            shown = result
        if os.path.isdir(testdata):
            for name in sorted(n for n in os.listdir(testdata) if n not in known):
                path = os.path.join(testdata, name)
                saved.append((path, os.path.relpath(os.path.realpath(path), base).replace(os.sep, '/')))
        # What the cache holds now is the corpus to keep
        replace_tree_from(inputs, cache)
    except Failure as e:
        error = str(e)
    # A hang has no input: the engine never saves the one that holds a worker
    conclude(last, [('crash', os.path.basename(name)) for path, name in saved] + ([('hang', '')] if hung else []), error, failed, saved)
    status = finish(leg, store, previous, last, findings_dir, saved, [log], shown)
    if module:
        shutil.rmtree(module, ignore_errors=True)
    return status


def cmd_go_run(args):
    leg = {'kind': 'go', 'id': args.id, 'package': args.package, 'test': args.test, 'canary': args.canary}
    return run_go(leg, args.seconds, args.seed, args.mode, args.store, args.findings)


# ---------------------------------------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------------------------------------

def evaluate(legs, stores, prefix, run_id, seconds):
    """The rows of the table and the problems of a run. stores: the directory that holds the artifacts <prefix>-<id> of the
    legs, each in a directory of its name"""
    rows, problems = [], []
    for leg in legs:
        path = os.path.join(stores, '%s-%s' % (prefix, leg['id']), 'manifest.json')
        row = {'leg': leg, 'manifest': None, 'status': ''}
        rows.append(row)
        try:
            with open(path, encoding='utf-8') as f:
                manifest = json.load(f)
        except (OSError, ValueError):
            row['status'] = 'no corpus stored'
            problems.append('%s: no stored corpus %s-%s with a readable manifest: the leg did not finish or did not upload'
                            % (leg['id'], prefix, leg['id']))
            continue
        row['manifest'] = manifest
        last = manifest.get('last') or {}
        if str(last.get('run_id')) != str(run_id):
            row['status'] = 'stale'
            problems.append('%s: the stored corpus is the one of run %s, not of this run (%s)' % (leg['id'], last.get('run_id'), run_id))
        elif leg['canary']:
            reported = last.get('result') == 'finding' and bool(last.get('findings'))
            row['status'] = 'planted fault reported' if reported else 'planted fault NOT reported'
            if not reported:
                problems.append('%s: the planted fault was not reported as a finding (%s)' % (leg['id'], last.get('result')))
        elif last.get('result') != 'clean':
            row['status'] = str(last.get('result', '?'))
            problems.append('%s: %s%s' % (leg['id'], last.get('result'), ': ' + last['message'] if last.get('message') else ''))
        elif float(last.get('seconds', 0)) < 0.9 * seconds - 5:
            row['status'] = 'ran short'
            problems.append('%s: fuzzed %.0f s of the %d s asked for, and found nothing: it ended early'
                            % (leg['id'], float(last.get('seconds', 0)), seconds))
        else:
            row['status'] = 'clean'
    return rows, problems


def report_text(rows, problems, mode, seconds):
    lines = ['### Fuzz campaign: %s, %d s for each target' % (mode, seconds), '',
             '| Target | Fuzzer | Result | Seconds | Executions | New | Stored files | Stored KB | Runs | Hours in all |',
             '|---|---|---|---:|---:|---:|---:|---:|---:|---:|']
    hours = {'c': 0, 'go': 0}
    real = {'c': 0, 'go': 0}
    for row in rows:
        leg, m = row['leg'], row['manifest']
        fuzzer = 'libFuzzer, AddressSanitizer' if leg['kind'] == 'c' else 'go test -fuzz'
        if not leg['canary']:
            real[leg['kind']] += 1
        if m is None:
            lines.append('| %s | %s | %s | | | | | | | |' % (leg['id'], fuzzer, row['status']))
            continue
        last = m.get('last') or {}
        if not leg['canary'] and float(m.get('total_seconds', 0)) >= ONE_HOUR:
            hours[leg['kind']] += 1
        lines.append('| %s | %s | %s | %.0f | %d | %d | %d | %.1f | %d | %.2f |'
                     % (leg['id'], fuzzer, row['status'], float(last.get('seconds', 0)), int(last.get('executions', 0)),
                        int(last.get('new_units', 0)), int(m.get('files', 0)), int(m.get('bytes', 0)) / 1024, int(m.get('runs', 0)),
                        float(m.get('total_seconds', 0)) / 3600))
    lines += ['', 'Targets that have fuzzed for at least one hour in all the runs that fed their stored corpus (criterion 1 of AUD-3): '
              'libFuzzer under AddressSanitizer %d of %d, Go %d of %d.' % (hours['c'], real['c'], hours['go'], real['go']), '']
    if problems:
        lines += ['**%d problems**' % len(problems), ''] + ['- %s' % p for p in problems] + ['']
    warnings = []
    for row in rows:
        if row['manifest']:
            warnings += ['%s: %s' % (row['leg']['id'], w) for w in (row['manifest'].get('last') or {}).get('warnings', [])]
    if warnings:
        lines += ['Warnings:', ''] + ['- %s' % w for w in warnings] + ['']
    return '\n'.join(lines)


def cmd_report(args):
    legs = json.loads(args.plan_c) + json.loads(args.plan_go)
    rows, problems = evaluate(legs, args.stores, args.prefix, args.run_id, args.seconds)
    text = report_text(rows, problems, args.mode, args.seconds)
    write_summary(text)
    print(text)
    for p in problems:
        annotate('error', p)
    return 1 if problems else 0


# ---------------------------------------------------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------------------------------------------------

def registry_lines(root, reg):
    """(directory, function, target, via, reason) of each line of the registry; the target is 'exempt' for an exemption. The
    reason is read whole: the registry cuts a line at its first '#', which a reason may hold (SDN-3 #179)"""
    lines = []
    with open(os.path.join(root, reg.REGISTRY), encoding='utf-8', errors='replace') as f:
        for line in f:
            text = line.strip()
            fields = text.split(None, 3)
            if text.startswith('#') or len(fields) < 3:
                continue
            via, reason = '', ''
            if fields[2] == 'exempt':
                reason = fields[3].strip() if len(fields) > 3 else ''
            elif len(fields) == 4 and fields[3].startswith('via '):
                via = fields[3][4:].split('#', 1)[0].strip()
            lines.append((fields[0], fields[1], fields[2], via, reason))
    return lines


def classify_exempt(reason):
    # A parser whose line says that its fuzz target is still to come has none; a line that names a target reads through it
    if re.search(r'still to come|not yet', reason, re.I):
        return 'pending'
    if re.search(r'\bfuzz_\w+|\bFuzz[A-Z]\w*', reason):
        return 'covered'
    return 'not a parser'


def parsers_report(root):
    """The text of the report, and the problems of the registry check (a parser that looks like one and has no line)"""
    reg = registry()
    problems = reg.check(root)
    counts = {'target': 0, 'covered': 0, 'not a parser': 0, 'pending': 0}
    pending = []
    for directory, function, target, via, reason in registry_lines(root, reg):
        if target != 'exempt':
            counts['target'] += 1
            continue
        kind = classify_exempt(reason)
        counts[kind] += 1
        if kind == 'pending':
            pending.append('- `%s` of %s: %s' % (function, directory, reason))
    lines = ['### Parsers and their fuzz targets (criterion 4 of AUD-3)', '',
             'The registry check (.github/scripts/fuzz-registry.py) refuses a parser of the new core that has no line in '
             '.github/quality/fuzz-targets.txt. This is every line of it, by what it says of the fuzz target:', '',
             '| | Functions |', '|---|---:|',
             '| with a fuzz target of its own (libFuzzer or Go) | %d |' % counts['target'],
             '| exempt: read through the fuzz target of another function | %d |' % counts['covered'],
             '| exempt: no parser, with its reason | %d |' % counts['not a parser'],
             '| **without a fuzz target (the line says that one is still to come)** | **%d** |' % counts['pending'],
             '| **looking like a parser, with no line (the check fails)** | **%d** |' % len(problems), '']
    if pending:
        lines += ['Parsers without a fuzz target:', ''] + pending + ['']
    if problems:
        lines += ['The check found:', ''] + ['- %s' % p for p in problems] + ['']
    return '\n'.join(lines), problems


def cmd_parsers(args):
    text, problems = parsers_report(args.root)
    write_summary(text)
    print(text)
    for p in problems:
        annotate('error', p)
    return 1 if problems else 0


# ---------------------------------------------------------------------------------------------------------------------
# regress
# ---------------------------------------------------------------------------------------------------------------------

def regress(findings, root):
    """Puts each saved input of a failed leg where it is replayed as a test. Returns the paths of the new files"""
    try:
        with open(os.path.join(findings, 'findings.json'), encoding='utf-8') as f:
            info = json.load(f)
    except (OSError, ValueError) as e:
        raise Failure('%s has no readable findings.json: %s' % (findings, e))
    made = []
    for name in info['files']:
        source = os.path.join(findings, *name.split('/'))
        if info['kind'] == 'c':
            m = ARTIFACT_RE.match(name)
            if not m:
                raise Failure('%s is not a file that libFuzzer saved for a finding' % name)
            relative = 'src/fuzz/corpus/%s/regress-%s-%s' % (info['target'], m.group('kind'), m.group('hash')[:12])
        else:
            # Saved under the path that go test replays it from, relative to the module
            relative = name
        target = os.path.join(root, *relative.split('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(source, target)
        made.append(relative)
    return made


def cmd_regress(args):
    for path in regress(args.findings, args.root):
        print('added %s' % path)
    print('Fix the code and commit these files with the fix: every full run replays them (src/fuzz/run_fuzzers.ps1 for a C target, '
          'go test for a Go one), so the finding cannot come back unseen.')
    return 0


# ---------------------------------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='The fuzz campaign of AUD-3: the long run of every fuzz target and the nightly run')
    sub = ap.add_subparsers(dest='command', required=True)

    p = sub.add_parser('plan', help='the legs, the seconds and the seed of a run')
    p.add_argument('--root', default=ROOT)
    p.add_argument('--event', help='default: GITHUB_EVENT_NAME')
    p.add_argument('--ref-name', help='default: GITHUB_REF_NAME')
    p.add_argument('--default-branch', help='default: DEFAULT_BRANCH')
    p.add_argument('--minutes', default='', help='workflow_dispatch: the minutes for each target (default %d)' % CAMPAIGN_MINUTES)
    p.add_argument('--targets', default='', help='workflow_dispatch: only the targets with one of these words in their id')
    p.add_argument('--output', help='default: GITHUB_OUTPUT, or standard output')
    p.set_defaults(run=cmd_plan)

    p = sub.add_parser('store-find', help='the newest stored corpus of a target')
    p.add_argument('--name', required=True, help='the artifact, fuzz-corpus-<id>')
    p.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'), help='default: GITHUB_REPOSITORY')
    p.add_argument('--branch', required=True, help='the default branch')
    p.add_argument('--output', help='default: GITHUB_OUTPUT, or standard output')
    p.set_defaults(run=cmd_store_find)

    for name, run in (('c-run', cmd_c_run), ('go-run', cmd_go_run)):
        p = sub.add_parser(name, help='one libFuzzer target' if name == 'c-run' else 'one Go fuzz test')
        p.add_argument('--id', required=True)
        if name == 'c-run':
            p.add_argument('--target', required=True, help='the fuzz_<name> of src/fuzz')
            p.add_argument('--max-len', type=int, required=True)
            p.add_argument('--build-dir', default='build')
        else:
            p.add_argument('--package', required=True, help='./controller/internal/control')
            p.add_argument('--test', required=True, help='FuzzOpen')
        p.add_argument('--seconds', type=int, required=True)
        p.add_argument('--seed', type=int, default=1)
        p.add_argument('--mode', default='')
        p.add_argument('--store', required=True, help='the directory of the stored corpus, restored before and uploaded after')
        p.add_argument('--findings', default='findings', help='where the inputs of the findings are saved')
        p.add_argument('--canary', action='store_true', help='the planted fault: it must end in a finding')
        p.set_defaults(run=run)

    p = sub.add_parser('report', help='the verdict of a run')
    p.add_argument('--stores', required=True, help='the directory that holds the artifacts <prefix>-<id>, each in a directory')
    p.add_argument('--prefix', required=True)
    p.add_argument('--run-id', default=os.environ.get('GITHUB_RUN_ID', ''))
    p.add_argument('--seconds', type=int, required=True)
    p.add_argument('--mode', default='')
    p.add_argument('--plan-c', required=True, help='the c_matrix of the plan')
    p.add_argument('--plan-go', required=True, help='the go_matrix of the plan')
    p.set_defaults(run=cmd_report)

    p = sub.add_parser('parsers', help='the parsers and their fuzz targets')
    p.add_argument('--root', default=ROOT)
    p.set_defaults(run=cmd_parsers)

    p = sub.add_parser('regress', help='the findings of a failed leg as regression tests')
    p.add_argument('--findings', required=True, help='the downloaded artifact fuzz-findings-<id>')
    p.add_argument('--root', default=ROOT)
    p.set_defaults(run=cmd_regress)

    args = ap.parse_args()
    # The log of a fuzzer may hold any byte: a console of Windows with a code page of its own must not fail on a character
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    try:
        return args.run(args)
    except Failure as e:
        annotate('error', str(e))
        return 1


if __name__ == '__main__':
    sys.exit(main())
