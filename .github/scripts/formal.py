# The formal model of the session handshake (AUD-5, #389; docs/formal-model.md).
#
# tests/formal holds the ProVerif models of the handshakes of Ranz VPN: the session of a client over TLS 1.3
# or QUIC, the control stream, Noise_IK alone and the peer layer. Each model is a list of files that this
# script joins into one input for ProVerif (tests/formal/variants.tsv), with its queries numbered by the
# (* @query id *) comments before them. tests/formal/expected.tsv says what each query must give in each
# variant, and tests/formal/model-to-code.tsv maps every name of the models to the function and the field of
# the code that it stands for.
#
# check    needs no prover: the variants and their files, the ids of the queries against expected.tsv, and the
#          table. Every file that the table names exists, every function that it names is defined in that file
#          (a C function with its body, a Go func), every field is in the body of one of the functions of its row,
#          every name that a model declares has a row and every row names a name that its model declares, and the
#          differences it cites (D1, D2, ...) are the ones that docs/formal-model.md describes, and the paths of
#          the pull_request trigger of formal.yml cover every file that the table names.
#          src/vpntest/formaltable.c refers to the C functions of the table that are not static, and check keeps
#          its list equal to them, in both directions. quality.yml runs it on every pull request.
# list     prints the matrix of formal.yml as matrix={"include":[...]}: a job for each slice of each variant (of the
#          variants named, all by default). A variant whose line of variants.tsv has a fourth column N runs its
#          queries as N ProVerif runs, the slices.
# version  says which ProVerif runs, and fails when it is not the pinned version.
# smoke    runs the prover on each variant for a few seconds (--timeout) and fails on an error that ProVerif reports at
#          once, a mistake of syntax or of types, so that the workflow stops before it starts one job for each slice.
# run      runs the pinned ProVerif on each variant and compares every result with expected.tsv. It fails on a
#          query that must hold and does not, on a negative control or a finding that stops showing its attack,
#          on an error of ProVerif or a timeout, and on any result that expected.tsv does not name. --slice I/K
#          runs one variant with only the I-th of K slices of its queries, which is what a job of formal.yml does.
#          formal.yml runs it in the full set.
# selftest the tests of this script, which need no prover.
#
# Usage:
#   python formal.py check [--root DIR]
#   python formal.py list [--root DIR] [VARIANT ...]
#   python formal.py version [--proverif PATH] [--version V]
#   python formal.py smoke [--root DIR] [--proverif PATH] [--out DIR] [--jobs N] [--timeout S] [VARIANT ...]
#   python formal.py run [--root DIR] [--proverif PATH] [--version V] [--out DIR] [--jobs N] [--timeout S]
#                        [--trace-lines N] [--slice I/K] [VARIANT ...]
#   python formal.py selftest
#
# Standard library only.

import argparse
import concurrent.futures
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time

MODEL_DIR = 'tests/formal'
VARIANTS = MODEL_DIR + '/variants.tsv'
EXPECTED = MODEL_DIR + '/expected.tsv'
TABLE = MODEL_DIR + '/model-to-code.tsv'
DOC = 'docs/formal-model.md'
VPNTEST = 'src/vpntest/formaltable.c'
WORKFLOW = '.github/workflows/formal.yml'

# What an expectation of expected.tsv accepts of the answer of ProVerif: "is true" (true), "is false" (false:
# an attack, with its trace) and "cannot be proved" (unproved)
EXPECT = {
    'holds': ('true',),
    'attack': ('false',),
    'fails': ('false', 'unproved'),
    'reach': ('false', 'unproved'),
    'any': ('true', 'false', 'unproved'),
}


class Anything(dict):
    # The expectation of the queries of an experiment (a variant that starts with try-): any answer is fine
    def __missing__(self, key):
        return ('any', '')

# The kinds of the rows of the table, and the ones that name no code
KINDS = ('process', 'function', 'constant', 'table', 'event', 'message', 'field', 'check', 'model')
CODELESS = ('model',)

RESULT_RE = re.compile(r'^RESULT (.*?)\s*(is true|is false|cannot be proved)\.?\s*$')
QUERY_RE = re.compile(r'\(\*\s*@query\s+([A-Za-z0-9-]+)\s*\*\)\s*query\s+([^.]*)\.', re.S)
COMMENT_RE = re.compile(r'\(\*.*?\*\)', re.S)


class Problem(Exception):
    pass


def read(path):
    with open(path, encoding='utf-8', newline='') as f:
        return f.read().replace('\r\n', '\n')


def read_tsv(path, columns):
    # The rows of a tab separated file, as (line number, fields): a line that starts with # and an empty line
    # are no rows, a row has at least `columns` fields and the last one may be missing when it is empty
    rows = []
    for number, line in enumerate(read(path).split('\n'), 1):
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split('\t')
        low, high = (columns if isinstance(columns, tuple) else (columns, columns))
        if len(fields) < low or len(fields) > high:
            raise Problem('%s:%d: %d fields, %s expected' % (path, number, len(fields), low if low == high else '%d to %d' % (low, high)))
        rows.append((number, [x.strip() for x in fields] + [''] * (high - len(fields))))
    return rows


# ---------------------------------------------------------------------------------------------------------------
# The variants and their queries
# ---------------------------------------------------------------------------------------------------------------

def load_variants(root):
    # {name: (files, what)}, in the order of the file
    variants = {}
    for number, f in read_tsv(os.path.join(root, VARIANTS), (3, 4)):
        name, files, what = f[0], [x.strip() for x in f[1].split(',') if x.strip()], f[2]
        if name in variants:
            raise Problem('%s:%d: the variant %s is listed twice' % (VARIANTS, number, name))
        if not files:
            raise Problem('%s:%d: the variant %s has no file' % (VARIANTS, number, name))
        variants[name] = (files, what)
    if not variants:
        raise Problem('%s lists no variant' % VARIANTS)
    return variants


def load_slices(root):
    # {name: how many ProVerif runs the queries of the variant are split over}: the fourth column of variants.tsv,
    # 1 when it has none. ProVerif keeps its state for every query of one run, so a variant with many queries or a
    # heavy one runs as several jobs, each with its own slice of the queries.
    slices = {}
    for number, f in read_tsv(os.path.join(root, VARIANTS), (3, 4)):
        count = f[3] or '1'
        if not count.isdigit() or int(count) < 1:
            raise Problem('%s:%d: the number of slices of %s is "%s", not a number from 1' % (VARIANTS, number, f[0], count))
        slices[f[0]] = int(count)
    return slices


def slice_ids(ids, index, count):
    # The query ids of slice index (counted from 1) of count: consecutive ones, of nearly equal number
    return ids[(index - 1) * len(ids) // count:index * len(ids) // count]


def build_text(root, files, keep=None):
    # The ProVerif input of a variant: its files, one after the other; with keep, only the queries of those ids
    parts = []
    for name in files:
        path = os.path.join(root, MODEL_DIR, name)
        if not os.path.isfile(path):
            raise Problem('%s names the file %s/%s, which does not exist' % (VARIANTS, MODEL_DIR, name))
        parts.append(read(path))
    text = '\n'.join(parts)
    if keep is not None:
        text = QUERY_RE.sub(lambda m: m.group(0) if m.group(1) in keep else '', text)
    return text


def kind_of(text):
    # What a query or a result is, by its text: the order of ProVerif's results is checked by this kind
    if 'inj-event' in text:
        return 'inj'
    if 'attacker' in text:
        return 'attacker'
    if '==>' in text:
        return 'corr'
    return 'reach'


def query_list(text):
    # [(id, kind)] of the queries of a ProVerif input, in the order in which they are written
    found = [(m.group(1), kind_of(m.group(2))) for m in QUERY_RE.finditer(text)]
    ids = [i for i, _ in found]
    for i in ids:
        if ids.count(i) > 1:
            raise Problem('the query id %s is used twice' % i)
    declared = len(re.findall(r'^query\b', COMMENT_RE.sub('', text), re.M))
    if declared != len(found):
        raise Problem('%d queries are written and %d have an (* @query id *) comment before them' % (declared, len(found)))
    return found


def load_expected(root):
    # {(variant, query): (expect, note)}
    expected = {}
    for number, f in read_tsv(os.path.join(root, EXPECTED), (3, 4)):
        variant, query, expect, note = f[0], f[1], f[2], f[3]
        if expect not in EXPECT:
            raise Problem('%s:%d: %s is no expectation (%s)' % (EXPECTED, number, expect, ', '.join(EXPECT)))
        if (variant, query) in expected:
            raise Problem('%s:%d: %s %s is listed twice' % (EXPECTED, number, variant, query))
        expected[(variant, query)] = (expect, note)
    return expected


def check_expected(variants, queries, expected):
    # The problems of expected.tsv against the queries of the variants. A variant whose name starts with try- is an
    # experiment (settings of the prover, a model that is being made faster): it has no expectation, and run reports
    # what ProVerif says of each of its queries without judging it.
    problems = []
    for name in variants:
        if name.startswith('try-'):
            continue
        for qid, _ in queries[name]:
            if (name, qid) not in expected:
                problems.append('%s: the query %s has no line in %s' % (name, qid, EXPECTED))
    for variant, query in expected:
        if variant not in variants:
            problems.append('%s names the variant %s, which %s does not list' % (EXPECTED, variant, VARIANTS))
        elif query not in [q for q, _ in queries[variant]]:
            problems.append('%s names the query %s, which the variant %s does not have' % (EXPECTED, query, variant))
    return problems


# ---------------------------------------------------------------------------------------------------------------
# The results of ProVerif
# ---------------------------------------------------------------------------------------------------------------

def parse_results(output):
    # [(verdict, text)] of the RESULT lines of ProVerif: verdict is true, false or unproved
    names = {'is true': 'true', 'is false': 'false', 'cannot be proved': 'unproved'}
    results = []
    for line in output.split('\n'):
        m = RESULT_RE.match(line.rstrip('\r'))
        if m:
            results.append((names[m.group(2)], m.group(1)))
    return results


def query_sections(output):
    # [lines] of each query in the output of ProVerif, in order: from its "Starting query" line to its RESULT line,
    # which is the derivation or the trace of an attack, or [] for every query when the two do not pair up
    starts, ends = [], []
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if line.startswith('Starting query '):
            starts.append(i)
        elif RESULT_RE.match(line.rstrip('\r')):
            ends.append(i)
    if len(starts) != len(ends) or any(s > e for s, e in zip(starts, ends)):
        return [[] for _ in ends]
    return [lines[s:e + 1] for s, e in zip(starts, ends)]


def compare(name, queries, results, expected):
    # [(query id, expect, verdict, ok)] of one variant: the n-th result is the n-th query. A count or a kind
    # that differs means that ProVerif did not answer the queries that were asked, in the order that they were
    # asked.
    if len(results) != len(queries):
        raise Problem('%s: %d queries and %d results of ProVerif' % (name, len(queries), len(results)))
    rows = []
    for (qid, kind), (verdict, text) in zip(queries, results):
        if kind_of(text) != kind:
            raise Problem('%s: the result for %s is "%s", which is not the answer to a query of kind %s' % (name, qid, text[:100], kind))
        expect = expected[(name, qid)][0]
        rows.append((qid, expect, verdict, verdict in EXPECT[expect]))
    return rows


VERDICT_TEXT = {'true': 'is true', 'false': 'is false (attack)', 'unproved': 'cannot be proved'}


def run_proverif(proverif, path, timeout):
    # (output, exit code or None on a timeout, seconds). The output of ProVerif goes to <path>.out as it comes, so
    # that the progress lines of run can say where a long run is, and a run that times out is killed and its output
    # kept.
    start = time.monotonic()
    out_path = path + '.out'
    with open(out_path, 'wb') as out:
        p = subprocess.Popen([proverif, '-in', 'pitype', path], stdout=out, stderr=subprocess.STDOUT)
        try:
            code = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            code = None
    with open(out_path, 'rb') as f:
        output = f.read().decode('utf-8', 'replace')
    return output, code, time.monotonic() - start


def tail_line(path):
    # The last line that ProVerif has written to the file so far, cut to 160 characters, or '' when there is none
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 2000))
            lines = [x for x in f.read().decode('utf-8', 'replace').split('\n') if x.strip()]
    except OSError:
        return ''
    return lines[-1][:160] if lines else ''


def peak_memory_mb():
    # The most memory that one of the child processes used so far, in MB, or 0 where the platform cannot say
    try:
        import resource
    except ImportError:
        return 0
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024


def proverif_version(proverif):
    try:
        p = subprocess.run([proverif, '-help'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    except OSError as e:
        raise Problem('cannot run %s: %s' % (proverif, e))
    m = re.search(r'proverif\s+(\d+(?:\.\d+)+\w*)', p.stdout.decode('utf-8', 'replace'), re.I)
    if not m:
        raise Problem('%s -help does not say which version of ProVerif it is' % proverif)
    return m.group(1)


def annotate(kind, message):
    if os.environ.get('GITHUB_ACTIONS'):
        print('::%s::%s' % (kind, message))
    else:
        print('%s: %s' % (kind, message))


def run(args):
    root = args.root
    variants = load_variants(root)
    texts = {n: build_text(root, f) for n, (f, _) in variants.items()}
    queries = {n: query_list(t) for n, t in texts.items()}
    problems = check_expected(variants, queries, load_expected(root))
    if problems:
        for p in problems:
            annotate('error', p)
        return 1

    if version_check(args) != 0:
        return 1
    version = proverif_version(args.proverif)

    names = args.variants or list(variants)
    for n in names:
        if n not in variants:
            raise Problem('no variant %s: %s' % (n, ', '.join(variants)))

    # --slice i/k: the queries of the one variant are cut into k slices, and this run takes the i-th; the other
    # queries are left out of its input, so that ProVerif has no state for them
    labels = {n: n for n in names}
    if args.slice:
        m = re.fullmatch(r'(\d+)/(\d+)', args.slice)
        if m is None or len(names) != 1:
            raise Problem('--slice i/k takes the one variant that is cut into slices, as 2/4 for the second of four')
        n, index, count = names[0], int(m.group(1)), int(m.group(2))
        ids = [q for q, _ in queries[n]]
        if not 1 <= index <= count <= len(ids):
            raise Problem('the slice %s is none of the %d queries of %s' % (args.slice, len(ids), n))
        texts[n] = build_text(root, variants[n][0], set(slice_ids(ids, index, count)))
        queries[n] = query_list(texts[n])
        if count > 1:
            labels[n] = '%s-%dof%d' % (n, index, count)

    os.makedirs(args.out, exist_ok=True)
    paths = {}
    for n in names:
        paths[n] = os.path.join(args.out, labels[n] + '.pv')
        with open(paths[n], 'w', encoding='utf-8', newline='\n') as f:
            f.write(texts[n])

    expected = load_expected(root)
    if all(n.startswith('try-') for n in names):
        expected = Anything(expected)
    summary = ['### Formal model: ProVerif %s' % version, '']

    def finish(n, output, code, seconds):
        # What one run gave, against expected.tsv: whether it is as expected, and its lines of the summary
        label = labels[n]
        with open(os.path.join(args.out, label + '.log'), 'w', encoding='utf-8', newline='\n') as f:
            f.write(output)
        results = parse_results(output)
        if code is None:
            annotate('error', '%s: ProVerif did not finish in %d s (peak memory %d MB)' % (label, args.timeout, peak_memory_mb()))
            # where it was: the last lines of its output, which say how far its rule base had grown
            print('::group::the last lines of ProVerif on %s' % label)
            print('\n'.join(output.rstrip().split('\n')[-40:]))
            print('::endgroup::')
            return False, ['- **%s**: timeout after %d s' % (label, args.timeout)]
        if code != 0 and not results:
            tail = '\n'.join(output.strip().split('\n')[-25:])
            annotate('error', '%s: ProVerif exited with %d:\n%s' % (label, code, tail))
            return False, ['- **%s**: ProVerif exited with %d' % (label, code)]
        try:
            rows = compare(n, queries[n], results, expected)
        except Problem as e:
            annotate('error', str(e))
            return False, ['- **%s**: %s' % (label, e)]
        bad = [r for r in rows if not r[3]]
        print('%s: %d queries in %.0f s, peak memory %d MB, %d not as expected' % (label, len(rows), seconds, peak_memory_mb(), len(bad)))
        # The derivation or the trace of each attack that the variant must show, in the log of the job (a group per
        # run) and in the file <label>.attacks.txt of the artifact
        sections = query_sections(output)
        attacks = [('=== %s %s ===' % (n, rows[i][0]), sections[i]) for i in range(len(rows))
                   if rows[i][1] == 'attack' and rows[i][2] == 'false' and sections[i]]
        if attacks:
            with open(os.path.join(args.out, label + '.attacks.txt'), 'w', encoding='utf-8', newline='\n') as f:
                f.write('\n'.join('%s\n%s\n' % (head, '\n'.join(body[-400:])) for head, body in attacks))
            if args.trace_lines > 0:
                print('::group::attacks of %s (the last %d lines of each)' % (label, args.trace_lines))
                print('\n'.join('%s\n%s\n' % (head, '\n'.join(body[-args.trace_lines:])) for head, body in attacks))
                print('::endgroup::')
        lines = ['#### %s (%.0f s)' % (label, seconds), '', '| query | expected | ProVerif | |', '|---|---|---|---|']
        for qid, expect, verdict, ok in rows:
            line = '%-22s expected %-7s ProVerif %s' % (qid, expect, VERDICT_TEXT[verdict])
            print('  %s%s' % (line, '' if ok else '   <-- NOT AS EXPECTED'))
            lines.append('| %s | %s | %s | %s |' % (qid, expect, VERDICT_TEXT[verdict], 'ok' if ok else '**not as expected**'))
        lines.append('')
        for qid, expect, verdict, _ in bad:
            note = expected[(n, qid)][1]
            annotate('error', '%s: %s must give %s (%s), and ProVerif says %s%s'
                     % (n, qid, expect, ' or '.join(EXPECT[expect]), VERDICT_TEXT[verdict], ' [%s]' % note if note else ''))
        return not bad, lines

    failed = 0
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        pending = {pool.submit(run_proverif, args.proverif, paths[n], args.timeout): n for n in names}
        # A variant is reported when it is done, and a minute without one says which are still to come
        while pending:
            done, _ = concurrent.futures.wait(list(pending), timeout=60, return_when=concurrent.futures.FIRST_COMPLETED)
            if not done:
                print('%.0f s: %d variants to come: %s' % (time.monotonic() - start, len(pending), ', '.join(sorted(
                    '%s [%s]' % (labels[v], tail_line(paths[v] + '.out')) for v in pending.values()))), flush=True)
                continue
            for future in done:
                n = pending.pop(future)
                ok, lines = finish(n, *future.result())
                summary += lines
                failed += 0 if ok else 1
                sys.stdout.flush()
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(summary) + '\n')
    if failed:
        print('%d of %d variants are not as expected' % (failed, len(names)))
        return 1
    print('every query of the %d variants gives what expected.tsv says' % len(names))
    return 0


# ---------------------------------------------------------------------------------------------------------------
# The table from the model to the code
# ---------------------------------------------------------------------------------------------------------------

def declared_names(text):
    # The names that a model file declares: processes, functions, destructors, events, tables, constants and free names
    text = COMMENT_RE.sub('', text)
    names = set()
    for m in re.finditer(r'^table\s+(\w+)\s*\(', text, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^(?:let|letfun)\s+(\w+)', text, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^fun\s+(\w+)\s*\(', text, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^reduc\s+forall[^;]*;\s*(\w+)\s*\(', text, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^event\s+(\w+)', text, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^const\s+([\w\s,]+?)\s*:', text, re.M):
        names.update(x.strip() for x in m.group(1).split(','))
    for m in re.finditer(r'^free\s+(\w+)\s*:', text, re.M):
        names.add(m.group(1))
    return names


def declaration_block(text, name):
    # The text of the let or letfun of a name, up to the line that ends it with a full stop, or None
    text = COMMENT_RE.sub('', text)
    m = re.search(r'^(?:let|letfun)\s+%s\b' % re.escape(name), text, re.M)
    if not m:
        return None
    end = re.search(r'\.[ \t]*$', text[m.start():], re.M)
    return text[m.start():m.start() + end.end()] if end else text[m.start():]


def has_word(text, word):
    return re.search(r'(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])' % re.escape(word), text) is not None


def c_close(text, start):
    # The index after the brace that closes the one at start, comments, strings and characters left aside
    depth, i, n = 0, start, len(text)
    while i < n:
        if text.startswith('//', i):
            i = text.find('\n', i)
            i = n if i < 0 else i
        elif text.startswith('/*', i):
            i = text.find('*/', i + 2)
            i = n if i < 0 else i + 2
        elif text[i] in '"\'':
            quote, i = text[i], i + 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == '\\' else 1
            i += 1
        else:
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
    return n


def c_function(text, name):
    # (first line, the whole definition) of a function in a C file, or None: a line that starts at the margin and holds
    # the name followed by a parameter list, which a left brace follows. A prototype and a call are not that.
    for m in re.finditer(r'(?<![A-Za-z0-9_])%s\s*\(' % re.escape(name), text):
        line_start = text.rfind('\n', 0, m.start()) + 1
        if not re.match(r'[A-Za-z_]', text[line_start:line_start + 1]) or re.match(r'(return|if|else|for|while|switch|case|goto|typedef)\b', text[line_start:]):
            continue
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        brace = re.match(r'\s*(?://[^\n]*\n\s*)*\{', text[i + 1:])
        if brace:
            end = text.find('\n', line_start)
            return text[line_start:end if end >= 0 else len(text)], text[line_start:c_close(text, i + brace.end())]
    return None


def c_definition(text, name):
    found = c_function(text, name)
    return found[0] if found else None


def c_defines(text, name):
    return c_function(text, name) is not None


def go_body(text, name):
    # The definition of a Go func, up to the closing brace at the margin, or None
    m = re.search(r'^func\s+(?:\([^)]*\)\s*)?%s\s*[\[(]' % re.escape(name), text, re.M)
    if not m:
        return None
    end = re.search(r'^}', text[m.start():], re.M)
    return text[m.start():m.start() + end.end()] if end else text[m.start():]


def go_defines(text, name):
    return go_body(text, name) is not None


def function_body(path, text, name):
    # The definition of a function of a Go or C file, or None
    if path.endswith('.go'):
        return go_body(text, name)
    found = c_function(text, name)
    return found[1] if found else None


def workflow_filters(root):
    # The path filters of the pull_request trigger of formal.yml, or None when the workflow is not there
    path = os.path.join(root, WORKFLOW)
    if not os.path.isfile(path):
        return None
    m = re.search(r'^    paths:[ \t]*\n((?:    (?:- |#)[^\n]*\n)+)', read(path), re.M)
    return [x.strip().strip('\'"') for x in re.findall(r'^    - (.*)$', m.group(1), re.M)] if m else []


def path_matches(pattern, path):
    # A path filter of GitHub Actions against a path: * is any characters but /, ** is any characters
    regex, i = '', 0
    while i < len(pattern):
        if pattern.startswith('**', i):
            regex, i = regex + '.*', i + 2
        elif pattern[i] == '*':
            regex, i = regex + '[^/]*', i + 1
        else:
            regex, i = regex + re.escape(pattern[i]), i + 1
    return re.fullmatch(regex, path) is not None


def doc_differences(root):
    # The ids D1, D2, ... that the headings of docs/formal-model.md describe
    path = os.path.join(root, DOC)
    if not os.path.isfile(path):
        raise Problem('%s does not exist' % DOC)
    return set(re.findall(r'^#+\s*(D\d+)\b', read(path), re.M))


def check_table(root, variants):
    problems = []
    models = {}
    for files, _ in variants.values():
        for name in files:
            if name not in models:
                models[name] = read(os.path.join(root, MODEL_DIR, name))
    declared = {name: declared_names(text) for name, text in models.items()}
    differences = doc_differences(root)
    cited = set()
    mapped = set()
    public = set()
    cache = {}

    for number, f in read_tsv(os.path.join(root, TABLE), 8):
        model, element, kind, file, function, field, diff, note = f
        where = '%s:%d' % (TABLE, number)
        if kind not in KINDS:
            problems.append('%s: the kind %s is none of %s' % (where, kind, ', '.join(KINDS)))
            continue
        base, _, member = element.partition(':')
        if model not in models:
            problems.append('%s: the model file %s is in no variant' % (where, model))
            continue
        if base not in declared[model]:
            problems.append('%s: %s does not declare %s' % (where, model, base))
        else:
            mapped.add((model, base))
        if member:
            block = declaration_block(models[model], base)
            if block is None or not has_word(block, member):
                problems.append('%s: the definition of %s in %s has no %s' % (where, base, model, member))
        if kind in ('message', 'field') and not member:
            problems.append('%s: a %s row names an element of a process as Process:name' % (where, kind))
        if diff != '-':
            if not re.fullmatch(r'D\d+', diff):
                problems.append('%s: the difference %s is not D<number> or -' % (where, diff))
            elif diff not in differences:
                problems.append('%s: %s describes no difference %s' % (where, DOC, diff))
            else:
                cited.add(diff)
        if kind in CODELESS:
            if not note:
                problems.append('%s: a model row has no note that says why it stands for no code' % where)
            continue
        if file == '-' or function == '-' or field == '-' or not file or not function or not field:
            problems.append('%s: the row names no file, function or field of the code' % where)
            continue
        path = os.path.join(root, file)
        if not os.path.isfile(path):
            problems.append('%s: the file %s does not exist' % (where, file))
            continue
        if file not in cache:
            cache[file] = read(path)
        text = cache[file]
        functions = [x.strip() for x in function.split(',')]
        bodies = []
        for fn in functions:
            body = function_body(file, text, fn)
            if body is None:
                problems.append('%s: %s defines no function %s' % (where, file, fn))
                continue
            bodies.append(body)
            if file.endswith('.c') and not c_definition(text, fn).lstrip().startswith('static'):
                public.add(fn)
        # A field is in the body of a function that the row names; when one of them is missing, anywhere in the file
        for fd in [x.strip() for x in field.split(',')]:
            if len(bodies) == len(functions):
                if not any(has_word(b, fd) for b in bodies):
                    problems.append('%s: the body of %s in %s has no %s' % (where, ' and '.join(functions), file, fd))
            elif not has_word(text, fd):
                problems.append('%s: %s has no %s' % (where, file, fd))

    for model, names in declared.items():
        for name in sorted(names):
            if (model, name) not in mapped:
                problems.append('%s declares %s, which no row of %s maps to the code' % (model, name, TABLE))
    for d in sorted(differences - cited):
        problems.append('%s describes %s, which no row of %s cites' % (DOC, d, TABLE))
    # A change of a file that the table names must run the prover on a pull request that carries the label full-ci
    filters = workflow_filters(root)
    if filters is None:
        problems.append('%s does not exist' % WORKFLOW)
    else:
        for file in sorted(cache):
            if not any(path_matches(p, file) for p in filters):
                problems.append('%s names %s, which no path of the pull_request trigger of %s covers: a change of it would not run the prover'
                                % (TABLE, file, WORKFLOW))
    problems += check_vpntest(root, public)
    return problems


def check_vpntest(root, public):
    # The public C functions of the table are the ones that src/vpntest/formaltable.c refers to, in both directions
    path = os.path.join(root, VPNTEST)
    if not os.path.isfile(path):
        return ['%s does not exist: the vpntest test that refers to the public C functions of the table' % VPNTEST]
    listed = set(re.findall(r'^\s*FORMAL\((\w+)\)', read(path), re.M))
    problems = []
    for name in sorted(public - listed):
        problems.append('%s does not refer to %s, a C function of %s that is not static' % (VPNTEST, name, TABLE))
    for name in sorted(listed - public):
        problems.append('%s refers to %s, which %s does not name as a C function that is not static' % (VPNTEST, name, TABLE))
    return problems


def smoke(args):
    # Every variant runs with the prover for a few seconds (--timeout), so that a mistake of syntax or of types, which
    # ProVerif reports at once, stops the workflow before it starts the jobs that would each report it
    variants = load_variants(args.root)
    names = args.variants or list(variants)
    for n in names:
        if n not in variants:
            raise Problem('no variant %s: %s' % (n, ', '.join(variants)))
    os.makedirs(args.out, exist_ok=True)
    paths = {}
    for n in names:
        paths[n] = os.path.join(args.out, 'smoke-%s.pv' % n)
        with open(paths[n], 'w', encoding='utf-8', newline='\n') as f:
            f.write(build_text(args.root, variants[n][0]))
    bad = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(run_proverif, args.proverif, paths[n], args.timeout): n for n in names}
        for future in concurrent.futures.as_completed(futures):
            n = futures[future]
            output, code, seconds = future.result()
            lines = output.split('\n')
            errors = [i for i, x in enumerate(lines) if re.match(r'(Error|Syntax error|Fatal)', x)]
            if errors or code not in (None, 0):
                bad += 1
                first = errors[0] if errors else max(0, len(lines) - 6)
                annotate('error', '%s: ProVerif reports an error (exit code %s):\n%s' % (n, code, '\n'.join(lines[max(0, first - 2):first + 3])))
            else:
                print('%s: %s' % (n, 'done in %.0f s' % seconds if code == 0 else 'running after %d s, no error' % args.timeout), flush=True)
    if bad:
        print('%d of %d variants do not run' % (bad, len(names)))
        return 1
    print('the %d variants run' % len(names))
    return 0


def version_check(args):
    # Which ProVerif runs, and whether it is the pinned version
    version = proverif_version(args.proverif)
    print('ProVerif %s' % version)
    if args.version and version != args.version:
        annotate('error', 'ProVerif %s runs, and the pinned version is %s' % (version, args.version))
        return 1
    return 0


def list_variants(args):
    # The matrix of formal.yml as one line of a workflow output, matrix={"include":[...]}: one job for each slice of
    # each variant (variants.tsv), which runs the slice that the job names, as "run --slice 2/4 tls443" does
    variants = load_variants(args.root)
    slices = load_slices(args.root)
    names = args.variants or list(variants)
    for name in names:
        if name not in variants:
            raise Problem('no variant %s: %s' % (name, ', '.join(variants)))
    include = []
    for name in names:
        count = slices[name]
        for index in range(1, count + 1):
            include.append({'variant': name, 'slice': '%d/%d' % (index, count),
                            'job': name if count == 1 else '%s (%d of %d)' % (name, index, count),
                            'slug': name if count == 1 else '%s-%dof%d' % (name, index, count)})
    print('matrix=' + json.dumps({'include': include}, separators=(',', ':')))
    return 0


def check(args):
    root = args.root
    try:
        variants = load_variants(root)
        texts = {n: build_text(root, f) for n, (f, _) in variants.items()}
        queries = {n: query_list(t) for n, t in texts.items()}
        problems = check_expected(variants, queries, load_expected(root))
        for name, count in load_slices(root).items():
            if count > len(queries[name]):
                problems.append('%s: %s cuts the %d queries of %s into %d slices' % (VARIANTS, name, len(queries[name]), name, count))
        problems += check_table(root, variants)
    except Problem as e:
        problems = [str(e)]
    for p in problems:
        annotate('error', p)
    if problems:
        print('%d problems in the formal model' % len(problems))
        return 1
    rows = len(read_tsv(os.path.join(root, TABLE), 8))
    print('formal model: %d variants, %d queries, %d rows of the table from the model to the code, all in order'
          % (len(variants), sum(len(q) for q in queries.values()), rows))
    return 0


# ---------------------------------------------------------------------------------------------------------------
# The tests of this script
# ---------------------------------------------------------------------------------------------------------------

def selftest():
    sample = '''
Starting query not event(ServerLoginOk(bob,alice,t))
RESULT not event(ServerLoginOk(bob,alice,t_1)) is false.
RESULT not attacker_p1(pw(alice[])) cannot be proved.
RESULT event(ServerAccept(bob,alice,t)) ==> event(ClientStart(alice,bob,t)) || event(LeakS(phase0,alice)) is true.
RESULT inj-event(ServerAccept(bob,alice,t)) ==> inj-event(ClientStart(alice,bob,t)) is true.
Verification summary:
Query not event(ServerLoginOk(bob,alice,t)) is false.
'''
    got = parse_results(sample)
    assert [v for v, _ in got] == ['false', 'unproved', 'true', 'true'], got
    assert [kind_of(t) for _, t in got] == ['reach', 'attacker', 'corr', 'inj'], got
    assert query_sections(sample) == [[], [], [], []], 'one start for four results'
    two = 'Starting query a\nderivation\nRESULT a is true.\nStarting query b\nRESULT b is false.\n'
    assert query_sections(two) == [['Starting query a', 'derivation', 'RESULT a is true.'], ['Starting query b', 'RESULT b is false.']]

    text = '''
(* a comment with query in it *)
(* @query one *)
query t: bitstring; event(A(t)).
(* @query two *)
query attacker(s) ==> event(B).
(* @query three *)
query t: bitstring; inj-event(A(t)) ==> inj-event(C(t)).
'''
    assert query_list(text) == [('one', 'reach'), ('two', 'attacker'), ('three', 'inj')]
    assert slice_ids(list('abcde'), 1, 2) == ['a', 'b'] and slice_ids(list('abcde'), 2, 2) == ['c', 'd', 'e'] and slice_ids(['a'], 1, 1) == ['a']
    assert sum((slice_ids(list(range(16)), i, 4) for i in range(1, 5)), []) == list(range(16)), 'the slices are the queries, each once'
    for bad, why in ((text + 'query event(D).\n', 'comment'), (text.replace('@query two', '@query one'), 'twice')):
        try:
            query_list(bad)
        except Problem:
            continue
        raise AssertionError('query_list accepted a text with a %s problem' % why)

    queries = query_list(text)
    expected = {('v', 'one'): ('reach', ''), ('v', 'two'): ('holds', ''), ('v', 'three'): ('attack', 'F9')}
    results = [('unproved', 'not event(A(t))'), ('true', 'not attacker(s)'), ('false', 'inj-event(A(t)) ==> inj-event(C(t))')]
    rows = compare('v', queries, results, expected)
    assert all(r[3] for r in rows), rows
    rows = compare('v', queries, [('true', 'not event(A(t))')] + results[1:], expected)
    assert [r[3] for r in rows] == [False, True, True]
    rows = compare('v', queries, results[:2] + [('unproved', 'inj-event(A(t)) ==> inj-event(C(t))')], expected)
    assert [r[3] for r in rows] == [True, True, False], 'an attack must be found, not just left unproved'
    for wrong in (results[:2], [results[1], results[0], results[2]]):
        try:
            compare('v', queries, wrong, expected)
        except Problem:
            continue
        raise AssertionError('compare accepted a result list that is not the answer to the queries')
    assert check_expected({'v': ([], '')}, {'v': queries}, expected) == []
    assert len(check_expected({'v': ([], '')}, {'v': queries}, {('v', 'one'): ('reach', ''), ('w', 'one'): ('reach', ''), ('v', 'four'): ('reach', '')})) == 4

    pv = '''
(* fun hidden(bitstring): bitstring. *)
type principal.
free c: channel.
const alice, bob: principal.
const empty: bitstring.
fun hash1(bitstring): bitstring.
reduc forall k: bitstring, m: bitstring; unaead(k, m) = m.
event Start(principal).
letfun spub(p: principal) = dhexp(skey(p), g).
let Client(me: principal, them: principal) =
  new e: bitstring;
  event Start(me).
'''
    assert declared_names(pv) == {'c', 'alice', 'bob', 'empty', 'hash1', 'unaead', 'Start', 'spub', 'Client'}, declared_names(pv)
    assert has_word(declaration_block(pv, 'Client'), 'e') and not has_word(declaration_block(pv, 'Client'), 'k')
    assert declaration_block(pv, 'Server') is None

    c = '''// A comment
#define NOISE_THING 1

static bool NoiseMixHash(NOISE_HANDSHAKE *hs, const void *data, UINT size);

static bool NoiseMixHash(NOISE_HANDSHAKE *hs, const void *data, UINT size) {
	return NoiseOther(hs);
}

bool NoiseSessionAccept(NOISE_SESSION *s, const NOISE_SESSION_CONFIG *cfg, UINT64 now, const UCHAR *record, UINT record_size,
                        UCHAR *reply, UINT max, UINT *reply_size) {
	if (NoiseCall(s)) {
		return NoiseHidden(s);
	}
}

static _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API QuicConnCallback(HQUIC connection, void *context, QUIC_CONNECTION_EVENT *event) {
}

bool NoiseProto(void);
'''
    for name in ('NoiseMixHash', 'NoiseSessionAccept', 'QuicConnCallback'):
        assert c_defines(c, name), name
    for name in ('NoiseOther', 'NoiseCall', 'NoiseHidden', 'NoiseProto', 'NoiseMissing', 'Mix'):
        assert not c_defines(c, name), name
    go = 'package control\n\nfunc handshake(ctx context.Context) error {\n}\n\nfunc (c *Conn) Read() (int, error) {\n}\n\nfunc Seal[T any](x T) {\n}\n'
    assert go_defines(go, 'handshake') and go_defines(go, 'Read') and go_defines(go, 'Seal')
    assert not go_defines(go, 'Write') and not go_defines(go, 'hand')
    assert path_matches('src/Core/Noise*', 'src/Core/NoiseSession.c') and not path_matches('src/Core/Noise*', 'src/Core/x/NoiseA.c')
    assert path_matches('tests/formal/**', 'tests/formal/session/tls443.pv') and not path_matches('tests/formal/**', 'tests/control/a.pv')
    assert path_matches('controller/internal/control/stream.go', 'controller/internal/control/stream.go') and not path_matches('a.c', 'abc')
    # The body of a function ends at its own closing brace, whatever braces its strings and comments hold
    c2 = ('int Hello(void) {\n\tchar *s = "}";\n\t// }\n\t/* } */\n\tchar q = \'}\';\n\tchar *t = "\\"}";\n\tif (q) {\n\t\treturn Inner;\n\t}\n}\n\n'
          'int Next(void) {\n\treturn Other;\n}\n')
    hello, nxt = c_function(c2, 'Hello'), c_function(c2, 'Next')
    assert hello[0] == 'int Hello(void) {' and has_word(hello[1], 'Inner') and not has_word(hello[1], 'Other'), hello
    assert has_word(nxt[1], 'Other') and not has_word(nxt[1], 'Inner') and c_function(c2, 'Missing') is None
    go2 = 'func handshake(ctx context.Context) error {\n\treturn exporter\n}\n\nfunc (c *Conn) Read() (int, error) {\n\treturn other\n}\n'
    assert has_word(go_body(go2, 'handshake'), 'exporter') and not has_word(go_body(go2, 'handshake'), 'other') and go_body(go2, 'Write') is None
    assert function_body('a.go', go2, 'Read') == go_body(go2, 'Read') and function_body('a.c', c2, 'Next') == nxt[1] and function_body('a.c', c2, 'Gone') is None

    with tempfile.TemporaryDirectory() as root:
        def put(path, content):
            full = os.path.join(root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)

        put(MODEL_DIR + '/m.pvl', 'const alice: principal.\nlet Client(me: principal) =\n  event Start(me).\nevent Start(principal).\n')
        put(MODEL_DIR + '/p.pv', 'process 0\n')
        put(VARIANTS, '# v\nv\tm.pvl,p.pv\tthe variant\n')
        put('src/Core/Noise.c', 'bool NoiseSessionConnect(NOISE_SESSION *s) {\n\tCopyMemory(s->HandshakeHash, 1);\n}\n\nstatic void NoiseHidden(void) {\n\tHandshakeHash = 0;\n}\n\n'
                                'static void NoiseOther(void) {\n\tElsewhere = 1;\n}\n')
        put(VPNTEST, 'static FORMAL_ENTRY formal_functions[] = {\n\tFORMAL(NoiseSessionConnect),\n};\n')
        covering = 'on:\n  pull_request:\n    types: [opened]\n    paths:\n    - \'tests/formal/**\'\n    # a comment between two filters\n    - "src/Core/Noise*"\n'
        assert workflow_filters(root) is None, 'no workflow'
        put(WORKFLOW, covering)
        assert workflow_filters(root) == ['tests/formal/**', 'src/Core/Noise*'], workflow_filters(root)
        put('docs/formal-model.md', '# The formal model\n\n### D1: a difference\n')
        rows = ['m.pvl\talice\tmodel\t-\t-\t-\t-\ta role of the model',
                'm.pvl\tClient\tprocess\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\tD1\t',
                'm.pvl\tClient:me\tfield\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t',
                'm.pvl\tStart\tevent\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t']
        put(TABLE, '\n'.join(rows) + '\n')
        variants = load_variants(root)
        assert check_table(root, variants) == [], check_table(root, variants)

        def table_problems(rows):
            put(TABLE, '\n'.join(rows) + '\n')
            return check_table(root, variants)

        ok = rows
        assert any('no row' in p or 'maps to the code' in p for p in table_problems(ok[:3]) + table_problems(ok[:1] + ok[2:])), 'a name without a row'
        assert any('defines no function' in p for p in table_problems([r.replace('NoiseSessionConnect', 'NoiseGone') for r in ok]))
        assert any('has no Missing' in p for p in table_problems([r.replace('HandshakeHash', 'Missing') for r in ok]))
        assert any('has no Elsewhere' in p for p in table_problems([r.replace('HandshakeHash', 'Elsewhere') for r in ok])), 'a field of another function'
        assert table_problems([r.replace('NoiseSessionConnect\tHandshakeHash', 'NoiseSessionConnect,NoiseOther\tHandshakeHash,Elsewhere') for r in ok]) == [], 'a field in one of two functions'
        assert any('does not exist' in p for p in table_problems([r.replace('src/Core/Noise.c', 'src/Core/None.c') for r in ok]))
        assert any('declare Nothing' in p for p in table_problems(ok + ['m.pvl\tNothing\tevent\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t']))
        assert any('definition of Client' in p for p in table_problems(ok + ['m.pvl\tClient:other\tfield\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t']))
        assert any('describes no difference' in p for p in table_problems([r.replace('\tD1\t', '\tD2\t') for r in ok]))
        assert any('cites' in p for p in table_problems([r.replace('\tD1\t', '\t-\t') for r in ok]))
        assert any('no file, function or field' in p for p in table_problems([r.replace('\tNoiseSessionConnect\tHandshakeHash\t', '\t-\t-\t') if 'process' in r else r for r in ok]))
        assert any('no note' in p for p in table_problems([ok[0].replace('a role of the model', '')] + ok[1:]))
        assert any('is in no variant' in p for p in table_problems(ok + ['x.pvl\talice\tmodel\t-\t-\t-\t-\tx']))
        assert any('Process:name' in p for p in table_problems(ok[:2] + ['m.pvl\tClient\tmessage\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t'] + ok[3:]))
        static = 'm.pvl\tClient:me\tfield\tsrc/Core/Noise.c\tNoiseHidden\tHandshakeHash\t-\t'
        put(VPNTEST, '')
        assert any('does not refer to NoiseSessionConnect' in p for p in table_problems(ok))
        put(VPNTEST, '\tFORMAL(NoiseSessionConnect),\n\tFORMAL(NoiseHidden),\n\tFORMAL(NoiseOther),\n')
        found = table_problems(ok + [static])
        assert any('refers to NoiseOther' in p for p in found) and any('refers to NoiseHidden' in p for p in found), found
        os.remove(os.path.join(root, VPNTEST))
        assert any('does not exist' in p and 'formaltable' in p for p in table_problems(ok))
        put(VPNTEST, '\tFORMAL(NoiseSessionConnect),\n')
        assert table_problems(ok + [static]) == [], 'a static function needs no entry'
        put(WORKFLOW, covering.replace('src/Core/Noise*', 'src/Cedar/**'))
        assert any('covers' in p and 'src/Core/Noise.c' in p for p in table_problems(ok)), 'a file of the table that the paths leave out'
        os.remove(os.path.join(root, WORKFLOW))
        assert any('does not exist' in p and 'formal.yml' in p for p in table_problems(ok))
        put(WORKFLOW, covering)
        put(TABLE, '\n'.join(ok[:1] + ['too\tfew']) + '\n')
        try:
            check_table(root, variants)
        except Problem:
            pass
        else:
            raise AssertionError('a row with too few fields was accepted')

    # run, with the prover made up: the variants, the order of the results, and each way that a run fails
    with tempfile.TemporaryDirectory() as root:
        def put(path, content):
            full = os.path.join(root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)

        def quiet(fn, *a):
            # run prints what it finds and annotates the errors of a made-up prover: none of that is for the log
            with contextlib.redirect_stdout(io.StringIO()):
                return fn(*a)

        put(MODEL_DIR + '/q.pvl', '(* @query one *)\nquery event(A).\n(* @query two *)\nquery attacker(s).\n')
        put(MODEL_DIR + '/p.pv', 'process 0\n')
        only_two = build_text(root, ['q.pvl'], {'two'})
        assert query_list(only_two) == [('two', 'attacker')] and 'query event(A)' not in only_two, only_two
        assert build_text(root, ['q.pvl']) == build_text(root, ['q.pvl'], {'one', 'two'}), 'every query kept is the whole text'
        for bad in ('0', 'x', '-1'):
            put(VARIANTS, 'v\tq.pvl,p.pv\tthe variant\t%s\n' % bad)
            try:
                load_slices(root)
            except Problem:
                continue
            raise AssertionError('load_slices accepted %s slices' % bad)
        put(VARIANTS, 'v\tq.pvl,p.pv\tthe variant\nw\tq.pvl,p.pv\tanother\t2\n')
        put(EXPECTED, 'v\tone\treach\nv\ttwo\tholds\nw\tone\treach\nw\ttwo\tattack\tF9\n')
        reach = 'Starting query not event(A)\nRESULT not event(A) is false.\n'
        secret = 'Starting query not attacker(s)\nRESULT not attacker(s) is %s.\n'
        canned = {'v': (reach + secret % 'true', 0, 1.0), 'w': (reach + secret % 'false', 0, 2.0)}
        real = (run_proverif, proverif_version)
        try:
            globals()['run_proverif'] = lambda proverif, path, timeout: canned[os.path.basename(path)[:-3]]
            globals()['proverif_version'] = lambda proverif: '2.05'
            listing = io.StringIO()
            with contextlib.redirect_stdout(listing):
                assert list_variants(argparse.Namespace(root=root, variants=[])) == 0
            assert json.loads(listing.getvalue().replace('matrix=', '', 1)) == {'include': [
                {'variant': 'v', 'slice': '1/1', 'job': 'v', 'slug': 'v'},
                {'variant': 'w', 'slice': '1/2', 'job': 'w (1 of 2)', 'slug': 'w-1of2'},
                {'variant': 'w', 'slice': '2/2', 'job': 'w (2 of 2)', 'slug': 'w-2of2'}]}, listing.getvalue()
            listing = io.StringIO()
            with contextlib.redirect_stdout(listing):
                assert list_variants(argparse.Namespace(root=root, variants=['v'])) == 0
            assert json.loads(listing.getvalue().replace('matrix=', '', 1)) == {'include': [{'variant': 'v', 'slice': '1/1', 'job': 'v', 'slug': 'v'}]}
            try:
                quiet(list_variants, argparse.Namespace(root=root, variants=['nope']))
            except Problem:
                pass
            else:
                raise AssertionError('list took a variant that variants.tsv does not have')
            args = argparse.Namespace(root=root, variants=[], proverif='proverif', version='2.05', out=os.path.join(root, 'out'),
                                      jobs=2, timeout=5, trace_lines=5, slice='')
            assert quiet(run, args) == 0, 'every result as expected'
            assert os.path.exists(os.path.join(root, 'out', 'w.attacks.txt')) and not os.path.exists(os.path.join(root, 'out', 'v.attacks.txt'))
            args.variants = ['w']
            assert quiet(run, args) == 0, 'one variant'
            # One slice of it: the other queries are not in its input, and its results are the answers to its own
            canned['w-1of2'] = (reach, 0, 1.0)
            canned['w-2of2'] = (secret % 'false', 0, 1.0)
            for index, kept, left in ((1, 'query event(A)', 'query attacker(s)'), (2, 'query attacker(s)', 'query event(A)')):
                args.slice = '%d/2' % index
                assert quiet(run, args) == 0, 'slice %d of 2' % index
                with open(os.path.join(root, 'out', 'w-%dof2.pv' % index), encoding='utf-8') as f:
                    sliced = f.read()
                assert kept in sliced and left not in sliced, sliced
            canned['w-2of2'] = (secret % 'true', 0, 1.0)
            assert quiet(run, args) == 1, 'an attack that must show and does not, in a slice'
            for wrong in ('0/2', '3/2', '1/3', 'one', '1/2 '):
                args.slice = wrong
                try:
                    quiet(run, args)
                except Problem:
                    continue
                raise AssertionError('run accepted the slice %s of two queries' % wrong)
            args.slice = '1/2'
            args.variants = ['v', 'w']
            try:
                quiet(run, args)
            except Problem:
                pass
            else:
                raise AssertionError('run took a slice of two variants')
            args.slice = ''
            args.variants = []
            canned['w'] = (reach + secret % 'true', 0, 2.0)
            assert quiet(run, args) == 1, 'an attack that must show and does not'
            canned['w'] = (reach + secret % 'false', 0, 2.0)
            canned['v'] = (reach + secret % 'unproved'.replace('unproved', 'false'), 0, 1.0)
            assert quiet(run, args) == 1, 'a query that must hold and does not'
            canned['v'] = ('', None, 5.0)
            assert quiet(run, args) == 1, 'a timeout'
            canned['v'] = ('Error: syntax error\n', 2, 0.1)
            assert quiet(run, args) == 1, 'an error of the prover'
            canned['v'] = (reach, 0, 1.0)
            assert quiet(run, args) == 1, 'a result missing'
            canned['v'] = (reach + secret % 'true', 0, 1.0)
            args.version = '2.04'
            assert quiet(run, args) == 1, 'the wrong version'
            # smoke: a variant that runs on (a timeout) or ends is fine, an error of the prover is not
            probe = argparse.Namespace(root=root, variants=[], proverif='proverif', out=os.path.join(root, 'smoke'), jobs=2, timeout=5)
            canned['smoke-v'] = ('Process:\n', None, 5.0)
            canned['smoke-w'] = (reach + secret % 'true', 0, 1.0)
            assert quiet(smoke, probe) == 0, 'a variant that runs on and one that ends'
            canned['smoke-v'] = ('File "smoke-v.pv", line 3, characters 5-8:\nError: Function pk is already defined.\n', 2, 0.1)
            assert quiet(smoke, probe) == 1, 'an error of the prover'
            canned['smoke-v'] = ('Process:\n', 2, 0.1)
            assert quiet(smoke, probe) == 1, 'an exit code that is not zero'
            probe.variants = ['nope']
            try:
                quiet(smoke, probe)
            except Problem:
                pass
            else:
                raise AssertionError('smoke took a variant that variants.tsv does not have')
        finally:
            globals()['run_proverif'], globals()['proverif_version'] = real
    print('formal selftest: ok')
    return 0


def main():
    ap = argparse.ArgumentParser(description='The formal model of the session handshake: check, list, version, smoke, run, selftest')
    ap.add_argument('mode', choices=['check', 'list', 'version', 'smoke', 'run', 'selftest'])
    ap.add_argument('variants', nargs='*', help='run: the variants to run, all by default')
    ap.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    ap.add_argument('--proverif', default='proverif', help='run: the ProVerif executable')
    ap.add_argument('--version', default='', help='run: the version that ProVerif must be, as it says')
    ap.add_argument('--out', default='build/formal', help='run: where the inputs and the logs go')
    ap.add_argument('--slice', default='', help='run: the one variant with only the i-th of k slices of its queries, as 2/4')
    ap.add_argument('--jobs', type=int, default=4, help='run: how many variants run at once')
    ap.add_argument('--timeout', type=int, default=1800, help='run: seconds that one variant may take')
    ap.add_argument('--trace-lines', type=int, default=0, help='run: print the last N lines of the trace of each attack that must show')
    args = ap.parse_args()
    try:
        if args.mode == 'selftest':
            return selftest()
        if args.mode == 'check':
            return check(args)
        if args.mode == 'list':
            return list_variants(args)
        if args.mode == 'version':
            return version_check(args)
        if args.mode == 'smoke':
            return smoke(args)
        return run(args)
    except Problem as e:
        annotate('error', str(e))
        return 1


if __name__ == '__main__':
    sys.exit(main())
