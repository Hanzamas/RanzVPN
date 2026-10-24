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
#          (a C function with its body, a Go func), every field is in the file, every name that a model declares
#          has a row and every row names a name that its model declares, and the differences it cites (D1, D2,
#          ...) are the ones that docs/formal-model.md describes. quality.yml runs it on every pull request.
# run      runs the pinned ProVerif on each variant and compares every result with expected.tsv. It fails on a
#          query that must hold and does not, on a negative control or a finding that stops showing its attack,
#          on an error of ProVerif or a timeout, and on any result that expected.tsv does not name.
#          formal.yml runs it in the full set.
# selftest the tests of this script, which need no prover.
#
# Usage:
#   python formal.py check [--root DIR]
#   python formal.py run [--root DIR] [--proverif PATH] [--version V] [--out DIR] [--jobs N] [--timeout S] [VARIANT ...]
#   python formal.py selftest
#
# Standard library only.

import argparse
import concurrent.futures
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

# What an expectation of expected.tsv accepts of the answer of ProVerif: "is true" (true), "is false" (false:
# an attack, with its trace) and "cannot be proved" (unproved)
EXPECT = {
    'holds': ('true',),
    'attack': ('false',),
    'fails': ('false', 'unproved'),
    'reach': ('false', 'unproved'),
}

# The kinds of the rows of the table, and the ones that name no code
KINDS = ('process', 'function', 'constant', 'event', 'message', 'field', 'check', 'model')
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
    for number, f in read_tsv(os.path.join(root, VARIANTS), 3):
        name, files, what = f[0], [x.strip() for x in f[1].split(',') if x.strip()], f[2]
        if name in variants:
            raise Problem('%s:%d: the variant %s is listed twice' % (VARIANTS, number, name))
        if not files:
            raise Problem('%s:%d: the variant %s has no file' % (VARIANTS, number, name))
        variants[name] = (files, what)
    if not variants:
        raise Problem('%s lists no variant' % VARIANTS)
    return variants


def build_text(root, files):
    # The ProVerif input of a variant: its files, one after the other
    parts = []
    for name in files:
        path = os.path.join(root, MODEL_DIR, name)
        if not os.path.isfile(path):
            raise Problem('%s names the file %s/%s, which does not exist' % (VARIANTS, MODEL_DIR, name))
        parts.append(read(path))
    return '\n'.join(parts)


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
    # The problems of expected.tsv against the queries of the variants
    problems = []
    for name in variants:
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
    # (output, exit code or None on a timeout, seconds)
    start = time.monotonic()
    try:
        p = subprocess.run([proverif, '-in', 'pitype', path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.stdout.decode('utf-8', 'replace'), p.returncode, time.monotonic() - start
    except subprocess.TimeoutExpired as e:
        return (e.stdout or b'').decode('utf-8', 'replace'), None, time.monotonic() - start


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

    version = proverif_version(args.proverif)
    print('ProVerif %s' % version)
    if args.version and version != args.version:
        annotate('error', 'ProVerif %s runs, and the pinned version is %s' % (version, args.version))
        return 1

    names = args.variants or list(variants)
    for n in names:
        if n not in variants:
            raise Problem('no variant %s: %s' % (n, ', '.join(variants)))
    os.makedirs(args.out, exist_ok=True)
    paths = {}
    for n in names:
        paths[n] = os.path.join(args.out, n + '.pv')
        with open(paths[n], 'w', encoding='utf-8', newline='\n') as f:
            f.write(texts[n])

    expected = load_expected(root)
    failed = 0
    summary = ['### Formal model: ProVerif %s' % version, '']
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {n: pool.submit(run_proverif, args.proverif, paths[n], args.timeout) for n in names}
        for n in names:
            output, code, seconds = futures[n].result()
            with open(os.path.join(args.out, n + '.log'), 'w', encoding='utf-8', newline='\n') as f:
                f.write(output)
            results = parse_results(output)
            if code is None:
                annotate('error', '%s: ProVerif did not finish in %d s' % (n, args.timeout))
                failed += 1
                summary += ['- **%s**: timeout after %d s' % (n, args.timeout)]
                continue
            if code != 0 and not results:
                tail = '\n'.join(output.strip().split('\n')[-12:])
                annotate('error', '%s: ProVerif exited with %d:\n%s' % (n, code, tail))
                failed += 1
                summary += ['- **%s**: ProVerif exited with %d' % (n, code)]
                continue
            try:
                rows = compare(n, queries[n], results, expected)
            except Problem as e:
                annotate('error', str(e))
                failed += 1
                summary += ['- **%s**: %s' % (n, e)]
                continue
            bad = [r for r in rows if not r[3]]
            print('%s: %d queries in %.0f s, %d not as expected' % (n, len(rows), seconds, len(bad)))
            summary += ['#### %s (%.0f s)' % (n, seconds), '', '| query | expected | ProVerif | |', '|---|---|---|---|']
            for qid, expect, verdict, ok in rows:
                line = '%-22s expected %-7s ProVerif %s' % (qid, expect, VERDICT_TEXT[verdict])
                print('  %s%s' % (line, '' if ok else '   <-- NOT AS EXPECTED'))
                summary.append('| %s | %s | %s | %s |' % (qid, expect, VERDICT_TEXT[verdict], 'ok' if ok else '**not as expected**'))
            summary.append('')
            for qid, expect, verdict, _ in bad:
                note = expected[(n, qid)][1]
                annotate('error', '%s: %s must give %s (%s), and ProVerif says %s%s'
                         % (n, qid, expect, ' or '.join(EXPECT[expect]), VERDICT_TEXT[verdict], ' [%s]' % note if note else ''))
            failed += 1 if bad else 0
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
    # The names that a model file declares: processes, functions, destructors, events, constants and free names
    text = COMMENT_RE.sub('', text)
    names = set()
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


def c_defines(text, name):
    # Whether a C file defines the function, with a body: a line that starts at the margin and holds the name
    # followed by a parameter list, which a left brace follows. A prototype and a call are not that.
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
        rest = text[i + 1:]
        if re.match(r'\s*(?://[^\n]*\n\s*)*\{', rest):
            return True
    return False


def go_defines(text, name):
    return re.search(r'^func\s+(?:\([^)]*\)\s*)?%s\s*[\[(]' % re.escape(name), text, re.M) is not None


def defines(path, text, name):
    if path.endswith('.go'):
        return go_defines(text, name)
    return c_defines(text, name)


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
        for fn in [x.strip() for x in function.split(',')]:
            if not defines(file, text, fn):
                problems.append('%s: %s defines no function %s' % (where, file, fn))
        for fd in [x.strip() for x in field.split(',')]:
            if not has_word(text, fd):
                problems.append('%s: %s has no %s' % (where, file, fd))

    for model, names in declared.items():
        for name in sorted(names):
            if (model, name) not in mapped:
                problems.append('%s declares %s, which no row of %s maps to the code' % (model, name, TABLE))
    for d in sorted(differences - cited):
        problems.append('%s describes %s, which no row of %s cites' % (DOC, d, TABLE))
    return problems


def check(args):
    root = args.root
    try:
        variants = load_variants(root)
        texts = {n: build_text(root, f) for n, (f, _) in variants.items()}
        queries = {n: query_list(t) for n, t in texts.items()}
        problems = check_expected(variants, queries, load_expected(root))
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

    with tempfile.TemporaryDirectory() as root:
        def put(path, content):
            full = os.path.join(root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)

        put(MODEL_DIR + '/m.pvl', 'const alice: principal.\nlet Client(me: principal) =\n  event Start(me).\nevent Start(principal).\n')
        put(MODEL_DIR + '/p.pv', 'process 0\n')
        put(VARIANTS, '# v\nv\tm.pvl,p.pv\tthe variant\n')
        put('src/Core/Noise.c', 'bool NoiseSessionConnect(NOISE_SESSION *s) {\n\tCopyMemory(s->HandshakeHash, 1);\n}\n')
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
        assert any('does not exist' in p for p in table_problems([r.replace('src/Core/Noise.c', 'src/Core/None.c') for r in ok]))
        assert any('declare Nothing' in p for p in table_problems(ok + ['m.pvl\tNothing\tevent\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t']))
        assert any('definition of Client' in p for p in table_problems(ok + ['m.pvl\tClient:other\tfield\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t']))
        assert any('describes no difference' in p for p in table_problems([r.replace('\tD1\t', '\tD2\t') for r in ok]))
        assert any('cites' in p for p in table_problems([r.replace('\tD1\t', '\t-\t') for r in ok]))
        assert any('no file, function or field' in p for p in table_problems([r.replace('\tNoiseSessionConnect\tHandshakeHash\t', '\t-\t-\t') if 'process' in r else r for r in ok]))
        assert any('no note' in p for p in table_problems([ok[0].replace('a role of the model', '')] + ok[1:]))
        assert any('is in no variant' in p for p in table_problems(ok + ['x.pvl\talice\tmodel\t-\t-\t-\t-\tx']))
        assert any('Process:name' in p for p in table_problems(ok[:2] + ['m.pvl\tClient\tmessage\tsrc/Core/Noise.c\tNoiseSessionConnect\tHandshakeHash\t-\t'] + ok[3:]))
        put(TABLE, '\n'.join(ok[:1] + ['too\tfew']) + '\n')
        try:
            check_table(root, variants)
        except Problem:
            pass
        else:
            raise AssertionError('a row with too few fields was accepted')
    print('formal selftest: ok')
    return 0


def main():
    ap = argparse.ArgumentParser(description='The formal model of the session handshake: check, run, selftest')
    ap.add_argument('mode', choices=['check', 'run', 'selftest'])
    ap.add_argument('variants', nargs='*', help='run: the variants to run, all by default')
    ap.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    ap.add_argument('--proverif', default='proverif', help='run: the ProVerif executable')
    ap.add_argument('--version', default='', help='run: the version that ProVerif must be, as it says')
    ap.add_argument('--out', default='build/formal', help='run: where the inputs and the logs go')
    ap.add_argument('--jobs', type=int, default=4, help='run: how many variants run at once')
    ap.add_argument('--timeout', type=int, default=1800, help='run: seconds that one variant may take')
    args = ap.parse_args()
    try:
        if args.mode == 'selftest':
            return selftest()
        if args.mode == 'check':
            return check(args)
        return run(args)
    except Problem as e:
        annotate('error', str(e))
        return 1


if __name__ == '__main__':
    sys.exit(main())
