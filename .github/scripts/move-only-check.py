# Move-only checker for the #29 structural split.
#
# Spec #29 has three code-commit kinds that are never mixed, each marked by its subject prefix:
#   "split: "    moves one group of whole functions, with their comments and the file-scope
#                declarations and macros only they use, out of one source file into one
#                destination file. Nothing else changes.
#   "header: "   moves declarations between headers, deletes declarations, changes #include lines.
#   "linkage: "  adds static to functions that one file uses and deletes their prototypes.
# The compiler and linker prove header and linkage commits and the harness goldens prove
# behaviour; this script proves that each commit is only of its kind.
#
# A split commit passes only when:
#   - exactly two files change: the source loses lines and gains none, the destination gains
#     lines and loses none, an existing destination only at its end;
#   - every block deleted from the source reappears byte for byte (line endings aside, which git
#     normalizes), in the same order, in the destination, and nothing else is added (blank lines
#     at file scope only separate blocks);
#   - every moved block starts and ends at file scope, with braces, parentheses, comments, line
#     continuations and #if/#endif balanced, and does not sit inside an #if of the source, so only
#     whole functions, declarations and macros move and none of them loses a condition;
#   - a new destination adds nothing before the moved blocks except a leading comment and
#     preprocessor lines of the source file's own preamble, in the source's order;
#   - a new header as destination (for example <Module>Internal.h, #29 open question 12 (a))
#     may also hold its include guard, and its source may gain exactly one line: the #include
#     of that header, in the preamble and outside any #if.
# A header commit may change only #include lines in .c files; in headers it may delete lines,
# re-add lines the commit deletes elsewhere (a move), change #include lines and, in a new
# header, add a leading comment and the include guard. A linkage commit may only add or remove
# "static " at the start of .c lines, delete header lines, and move static prototypes out of a
# .c file into a header of the module without "static " (#29 open question 1 (a)); each moved
# prototype must reappear in a header word for word. A function that loses "static " and has
# no static prototype to move (it is defined before its first use) may be declared in such a
# header by its one-line definition head, word for word, followed by ";".
#
# With --range, every marked commit in the range is checked. An unmarked commit made after this
# checker landed fails when it moves a whole file-scope block (function, declaration or macro) of
# MIN_MOVE or more lines verbatim into another file, because a move must be its own split commit;
# extracting part of a function is a refactor and is not flagged. Merge commits are not checked: their
# conflict resolutions are covered by the compiler and the goldens only. Commits listed in
# .github/move-only-waivers.txt (one "<sha> <reason>" per line) are reported and skipped, so a
# mistake that already landed can be fixed forward without rewriting history.
#
# On failure the checker names the first line that breaks a rule and exits 1.
#
# Usage:
#   python -I move-only-check.py [--repo DIR] COMMIT...
#   python -I move-only-check.py [--repo DIR] --range BASE..HEAD

import argparse
import os
import re
import subprocess
import sys

PREFIXES = (('split: ', 'split'), ('header: ', 'header'), ('linkage: ', 'linkage'))
MIN_MOVE = 4
SELF = '.github/scripts/move-only-check.py'
WAIVERS = '.github/move-only-waivers.txt'
DIRECTIVE = re.compile(r'\s*#\s*(\w*)\s*(\S*)')
HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')

# Lexer state before a line: brace depth, parenthesis depth, inside /* */, the previous line ended
# with a backslash, #if depth, the logical line is a preprocessor directive, the previous line
# was a // comment continued by a backslash.
START = (0, 0, False, False, 0, False, False)


class Fail(Exception):
    pass


def git(repo, *args):
    p = subprocess.run(['git', '-c', 'core.quotepath=false'] + list(args), cwd=repo,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.decode('utf-8', 'replace').strip()))
    return p.stdout


def lines_of(repo, rev, path):
    # Bytes 1:1 as latin-1, except the line ending: .gitattributes (text=auto) stores a new file
    # with LF while older blobs keep CRLF, and checkout writes both the same way, so a trailing CR
    # is not part of the line. Every other byte, a CR inside a line included, is compared exactly.
    text = git(repo, 'cat-file', 'blob', '%s:%s' % (rev, path)).decode('latin-1')
    lines = text.split('\n')
    if lines[-1] == '':
        lines.pop()
    return [ln[:-1] if ln.endswith('\r') else ln for ln in lines]


def scan(line, st):
    """Lex one line from state st; return (state after the line, whether it holds code)."""
    brace, paren, comment, cont, cond, pp, lc = st
    s = line[:-1] if line.endswith('\r') else line
    if lc:
        more = s.endswith('\\')
        return (brace, paren, comment, more, cond, pp, more), False
    if not cont:
        pp = False
        if not comment:
            m = DIRECTIVE.match(s)
            if m and s.lstrip().startswith('#'):
                pp = True
                d = m.group(1)
                if d in ('if', 'ifdef', 'ifndef'):
                    cond += 1
                elif d == 'endif':
                    cond -= 1
    code = False
    quote = None
    linecomment = False
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if comment:
            if s.startswith('*/', i):
                comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if c == '\\':
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if s.startswith('//', i):
            linecomment = True
            break
        if s.startswith('/*', i):
            comment = True
            i += 2
            continue
        if not pp and not c.isspace():
            code = True
        if c == '"' or c == "'":
            quote = c
        elif not pp:
            if c == '{':
                brace += 1
            elif c == '}':
                brace -= 1
            elif c == '(':
                paren += 1
            elif c == ')':
                paren -= 1
        i += 1
    cont = s.endswith('\\')
    return (brace, paren, comment, cont, cond, pp, linecomment and cont), code


def states(lines, st=START):
    out, codes = [st], []
    for ln in lines:
        st, code = scan(ln, st)
        out.append(st)
        codes.append(code)
    return out, codes


def clean(st):
    return st[0] == 0 and st[1] == 0 and not st[2] and not st[3] and not st[6]


def blank(ln):
    return ln.strip() == ''


def chunks(lines, first, st=START):
    """Blocks of lines separated by blank lines at file scope: [(line number, tuple of lines)]."""
    out, cur, at = [], [], 0
    for k, ln in enumerate(lines):
        if blank(ln) and clean(st):
            if cur:
                out.append((at, tuple(cur)))
                cur = []
        else:
            if not cur:
                at = first + k
            cur.append(ln)
        st, _ = scan(ln, st)
    if cur:
        out.append((at, tuple(cur)))
    return out


def hunks(repo, a, b, path):
    out = git(repo, 'diff', '-U0', '--no-color', '--no-ext-diff', '--no-textconv', '--text',
              '--no-renames', '--diff-algorithm=myers', a, b, '--', path).decode('latin-1')
    res = []
    for ln in out.split('\n'):
        m = HUNK.match(ln)
        if m:
            res.append((int(m.group(1)), int(m.group(2) or '1'), int(m.group(3)), int(m.group(4) or '1')))
    return res


def changed_files(repo, p, c):
    out = git(repo, 'diff-tree', '-r', '-z', '--no-renames', '--raw', p, c).decode('utf-8', 'replace')
    parts = out.split('\0')
    res, i = [], 0
    while i < len(parts) - 1:
        if not parts[i].startswith(':'):
            i += 1
            continue
        f = parts[i][1:].split(' ')
        res.append((f[4][0], parts[i + 1], f[0], f[1]))
        i += 2
    return res


def text_mode(om, nm):
    # Regular files only: a submodule (160000) or a symbolic link (120000) has no lines to compare.
    return all(m in ('000000', '100644', '100755') for m in (om, nm))


def no_special(files, kind):
    for status, path, om, nm in files:
        if not text_mode(om, nm):
            raise Fail('%s: a %s commit changes no submodule or symbolic link (mode %s to %s)' % (path, kind, om, nm))
    return files


def directive(ln):
    m = DIRECTIVE.match(ln)
    return m.group(1) if m and ln.lstrip().startswith('#') else None


def run_error(S, a, b):
    """Why the deleted run [a, b) is not a whole file-scope block, or None."""
    if not clean(S[a]):
        return a, 'starts inside a function, comment, parenthesis or continued line'
    if S[a][4] != 0:
        return a, 'sits inside an #if of the source; move the whole #if ... #endif group'
    for k in range(a + 1, b + 1):
        if S[k][0] < 0 or S[k][4] < 0:
            return k - 1, 'closes a brace or an #if that it did not open'
    if not clean(S[b]):
        return b - 1, 'ends inside a function, comment, parenthesis or continued line'
    if S[b][4] != 0:
        return b - 1, 'leaves an #if open'
    return None


def place(P, S, s, e, lo, hi):
    """Slide the deleted run P[s:e] (diff placement is ambiguous) to where it is a whole block."""
    cands = [(s, e)]
    a, b = s, e
    while a > lo and P[a - 1] == P[b - 1]:
        a, b = a - 1, b - 1
        cands.append((a, b))
    a, b = s, e
    while b < hi and P[a] == P[b]:
        a, b = a + 1, b + 1
        cands.append((a, b))
    for a, b in cands:
        if run_error(S, a, b) is None:
            return a, b, None
    return s, e, run_error(S, s, e)


def compare(moved, body, spath, dpath):
    mv = [m[1] for m in moved]
    bd = [b[1] for b in body]
    if mv == bd:
        return
    if sorted(mv) == sorted(bd):
        for (sl, ms), (dl, bs) in zip(moved, body):
            if ms != bs:
                raise Fail('%s:%d: moved blocks must keep their relative order (this block comes from %s:%d)'
                           % (dpath, dl, spath, moved[mv.index(bs)][0]))
    for i in range(max(len(mv), len(bd))):
        if i >= len(bd):
            raise Fail('%s:%d: deleted block does not reappear in %s' % (spath, moved[i][0], dpath))
        if i >= len(mv):
            raise Fail('%s:%d: line added that is not part of a moved block' % (dpath, body[i][0]))
        ms, bs = mv[i], bd[i]
        if ms == bs:
            continue
        for k in range(max(len(ms), len(bs))):
            if k >= len(bs):
                raise Fail('%s:%d: deleted line does not reappear in %s' % (spath, moved[i][0] + k, dpath))
            if k >= len(ms):
                raise Fail('%s:%d: line added that is not part of a moved block' % (dpath, body[i][0] + k))
            if ms[k] != bs[k]:
                raise Fail('%s:%d: differs from %s:%d; a moved block stays byte for byte the same'
                           % (dpath, body[i][0] + k, spath, moved[i][0] + k))


def check_preamble(P, S, codes, D, DS, dcodes, end, spath, dpath):
    first_code = next((k for k, c in enumerate(codes) if c), len(P))
    allowed = [P[k] for k in range(first_code) if S[k + 1][5]]
    j, header = 0, True
    for k in range(end):
        ln = D[k]
        if blank(ln):
            continue
        if DS[k + 1][5]:
            header = False
            while j < len(allowed) and allowed[j] != ln:
                j += 1
            if j == len(allowed):
                raise Fail('%s:%d: a new destination may add before the moved blocks only a leading comment and '
                           'preprocessor lines of the preamble of %s, in its order; this line is neither'
                           % (dpath, k + 1, spath))
            j += 1
            continue
        if header and not dcodes[k]:
            continue
        raise Fail('%s:%d: line added that is not part of a moved block' % (dpath, k + 1))
    if not clean(DS[end]) or DS[end][4] != 0:
        raise Fail('%s:%d: the preamble leaves a comment or an #if open' % (dpath, max(end, 1)))


def greedy_preamble(D, DS, dcodes):
    header = True
    for k, ln in enumerate(D):
        if blank(ln) or DS[k + 1][5]:
            header = header and not DS[k + 1][5]
            continue
        if header and not dcodes[k]:
            continue
        return k
    return len(D)


def check_split(repo, p, c):
    files = no_special(changed_files(repo, p, c), 'split')
    if len(files) != 2:
        raise Fail('a split commit changes exactly two files, its source and its destination; this one changes %d: %s'
                   % (len(files), ', '.join(f[1] for f in files)))
    src = dst = None
    for status, path, om, nm in files:
        if status == 'A':
            if dst:
                raise Fail('%s: a split commit has one destination' % path)
            dst = (path, None)
            continue
        if status != 'M' or om != nm:
            raise Fail('%s: a split commit only edits its source and its destination (status %s, mode %s to %s)'
                       % (path, status, om, nm))
        hs = hunks(repo, p, c, path)
        adds = [h for h in hs if h[3] > 0]
        dels = [h for h in hs if h[1] > 0]
        if dels:
            if src:
                raise Fail('%s: a split commit has one source' % path)
            src = (path, hs)
        else:
            if dst:
                raise Fail('%s: a split commit has one destination' % path)
            dst = (path, hs)
    if not src or not dst:
        raise Fail('a split commit deletes from one file and adds to another')

    spath, shunks = src
    dpath, dhunks = dst
    # #29 open question 12 (a): a split into a NEW header (for example <Module>Internal.h) may add
    # exactly one line to its source: the #include of that header, in the preamble, outside any #if.
    new_header = dhunks is None and dpath.endswith('.h')
    added = [h for h in shunks if h[3] > 0]
    if added:
        C = lines_of(repo, c, spath)
        CS, ccodes = states(C)
        include = '#include "%s"' % dpath.rsplit('/', 1)[-1]
        lines_added = [(h[2] - 1 + k) for h in added for k in range(h[3])]
        k = lines_added[0]
        if not new_header or len(lines_added) != 1 or C[k].strip() != include:
            raise Fail('%s:%d: a split commit adds nothing to its source, except the one #include of a new header '
                       'it creates' % (spath, k + 1))
        if any(ccodes[:k]) or CS[k][4] != 0 or not clean(CS[k]):
            raise Fail('%s:%d: the #include of the new header goes in the preamble, outside any #if' % (spath, k + 1))
    P = lines_of(repo, p, spath)
    S, codes = states(P)
    runs = [(h[0] - 1, h[0] - 1 + h[1]) for h in shunks if h[1] > 0]
    moved, prev = [], 0
    for i, (s, e) in enumerate(runs):
        hi = runs[i + 1][0] if i + 1 < len(runs) else len(P)
        a, b, err = place(P, S, s, e, prev, hi)
        if err:
            raise Fail('%s:%d: the moved block %s' % (spath, err[0] + 1, err[1]))
        moved.extend(chunks(P[a:b], a + 1))
        prev = b

    D = lines_of(repo, c, dpath)
    if new_header:
        # The include guard of the new header is neither moved code nor preamble: blank it out.
        for k in guard_lines(D):
            D[k] = ''
    if dhunks is not None:
        Q = lines_of(repo, p, dpath)
        while Q and blank(Q[-1]):
            Q.pop()
        for k, ln in enumerate(Q):
            if k >= len(D) or D[k] != ln:
                raise Fail('%s:%d: an existing destination grows only at its end' % (dpath, k + 1))
        QS, _ = states(Q)
        if not clean(QS[-1]) or QS[-1][4] != 0:
            raise Fail('%s:%d: the destination does not end at file scope' % (dpath, len(Q)))
        compare(moved, chunks(D[len(Q):], len(Q) + 1), spath, dpath)
        return
    DS, dcodes = states(D)
    whole = chunks(D, 1)
    n = len(moved)
    if n and len(whole) >= n and [w[1] for w in whole[-n:]] == [m[1] for m in moved]:
        check_preamble(P, S, codes, D, DS, dcodes, whole[-n][0] - 1, spath, dpath)
        return
    # The moved blocks are not the tail of the file: find where the preamble ends to name the
    # first line that breaks a rule.
    end = greedy_preamble(D, DS, dcodes)
    check_preamble(P, S, codes, D, DS, dcodes, end, spath, dpath)
    compare(moved, chunks(D[end:], end + 1, DS[end]), spath, dpath)


def guard_lines(new):
    """Line indexes of the include guard of a header: #ifndef X, #define X and the last #endif."""
    idx = [k for k, ln in enumerate(new) if directive(ln)]
    if len(idx) < 3:
        return set()
    m1, m2 = DIRECTIVE.match(new[idx[0]]), DIRECTIVE.match(new[idx[1]])
    if m1.group(1) == 'ifndef' and m2.group(1) == 'define' and m1.group(2) == m2.group(2) \
            and new[idx[1]].split()[2:] == [] and directive(new[idx[-1]]) == 'endif':
        return {idx[0], idx[1], idx[-1]}
    return set()


def check_header(repo, p, c):
    deleted, added = set(), []
    for status, path, om, nm in no_special(changed_files(repo, p, c), 'header'):
        if not path.endswith(('.c', '.h')) or om != nm and status == 'M':
            raise Fail('%s: a header commit changes only the text of .c and .h files' % path)
        if status not in 'AMD':
            raise Fail('%s: a header commit adds, edits or deletes files (status %s)' % (path, status))
        if path.endswith('.c') and status != 'M':
            raise Fail('%s: a header commit does not add or delete .c files' % path)
        old = lines_of(repo, p, path) if status != 'A' else []
        new = lines_of(repo, c, path) if status != 'D' else []
        guard = guard_lines(new) if status == 'A' else set()
        top = next((k for k, ln in enumerate(new) if not blank(ln) and not ln.lstrip().startswith('//')), len(new))
        for os_, oc, ns, nc in hunks(repo, p, c, path):
            for k in range(os_ - 1, os_ - 1 + oc) if oc else ():
                if path.endswith('.c') and not blank(old[k]) and directive(old[k]) != 'include':
                    raise Fail('%s:%d: a header commit changes only #include lines in a .c file' % (path, k + 1))
                deleted.add(old[k])
            for k in range(ns - 1, ns - 1 + nc) if nc else ():
                ln = new[k]
                if blank(ln) or directive(ln) == 'include':
                    continue
                if path.endswith('.c'):
                    raise Fail('%s:%d: a header commit changes only #include lines in a .c file' % (path, k + 1))
                if k in guard or (status == 'A' and k < top):
                    continue
                added.append((path, k + 1, ln))
    for path, k, ln in added:
        if ln not in deleted:
            raise Fail('%s:%d: a header commit only moves, deletes or includes; this line is new' % (path, k))


def static_prototype(ln):
    s = ln.strip()
    return s.startswith('static ') and '(' in s and s.endswith(');') and '{' not in s and '=' not in s


def definition_head(ln):
    """True for the one-line head of a function definition: 'type name(params)' with nothing after."""
    s = ln.strip()
    return '(' in s and s.endswith(')') and not any(ch in s for ch in ';={}') and not s.startswith('#')


def check_linkage(repo, p, c):
    # Both directions of #29: "static " added to a function one file uses (its header prototype
    # deleted), or, open question 1 (a), "static " removed so a group can move to another file of
    # the module, its static prototype moving without "static " to a header of that module. A
    # function that loses "static " but has no static prototype is declared by its definition head.
    files = no_special(changed_files(repo, p, c), 'linkage')
    moved_protos, h_deleted, h_added, heads = set(), set(), [], set()
    for status, path, om, nm in files:
        if not path.endswith(('.c', '.h')) or om != nm and status == 'M':
            raise Fail('%s: a linkage commit only edits .c and .h files' % path)
        if status != 'M' and not (status == 'A' and path.endswith('.h')):
            raise Fail('%s: a linkage commit edits files and may add a header, nothing else (status %s)' % (path, status))
        old = lines_of(repo, p, path) if status != 'A' else []
        new = lines_of(repo, c, path)
        guard = guard_lines(new) if status == 'A' else set()
        top = next((k for k, ln in enumerate(new) if not blank(ln) and not ln.lstrip().startswith('//')), len(new))
        for os_, oc, ns, nc in hunks(repo, p, c, path):
            dels = list(range(os_ - 1, os_ - 1 + oc)) if oc else []
            adds = list(range(ns - 1, ns - 1 + nc)) if nc else []
            if path.endswith('.h'):
                h_deleted.update(old[k] for k in dels)
                for k in adds:
                    if blank(new[k]) or directive(new[k]) == 'include' or k in guard or (status == 'A' and k < top):
                        continue
                    h_added.append((path, k + 1, new[k]))
                continue
            # .c: every added line is a deleted line with "static " added or removed, in order;
            # every other deleted line is blank or a static prototype that moves to a header.
            j = 0
            for k in adds:
                a = new[k]
                while j < len(dels) and not (a == 'static ' + old[dels[j]] or old[dels[j]] == 'static ' + a):
                    d = old[dels[j]]
                    if not blank(d) and not static_prototype(d):
                        raise Fail('%s:%d: a linkage commit only adds or removes "static " and moves static prototypes '
                                   'to a header' % (path, dels[j] + 1))
                    if not blank(d):
                        moved_protos.add(d.strip()[len('static '):])
                    j += 1
                if j == len(dels):
                    raise Fail('%s:%d: a linkage commit only adds or removes "static "' % (path, k + 1))
                if old[dels[j]] == 'static ' + a and definition_head(a):
                    heads.add(a.strip() + ';')
                j += 1
            for i in dels[j:]:
                d = old[i]
                if blank(d):
                    continue
                if not static_prototype(d):
                    raise Fail('%s:%d: a linkage commit only adds or removes "static " and moves static prototypes '
                               'to a header' % (path, i + 1))
                moved_protos.add(d.strip()[len('static '):])
    for path, k, ln in h_added:
        if ln.strip() not in moved_protos and ln not in h_deleted and ln.strip() not in heads:
            raise Fail('%s:%d: a linkage commit adds to a header only prototypes it removes "static " from, '
                       'declarations of definitions it removes "static " from, or lines it moves from another header'
                       % (path, k))
    placed = {ln.strip() for _, _, ln in h_added}
    for proto in sorted(moved_protos):
        if proto not in placed:
            raise Fail('a linkage commit deletes the static prototype "%s" but declares it in no header' % proto)


def whole_blocks(P, S, codes, a, b):
    """The file-scope blocks (whole functions, declarations, macros) inside the deleted run [a, b)."""
    out, start = [], None
    for k in range(a, b + 1):
        if k == b or (blank(P[k]) and clean(S[k])):
            if start is not None and clean(S[start]) and clean(S[k]) and any(codes[start:k]):
                block = P[start:k]
                if sum(1 for x in block if not blank(x)) >= MIN_MOVE:
                    out.append((start + 1, block))
            start = None
        elif start is None:
            start = k
    return out


def check_unmarked(repo, p, c):
    # Only whole file-scope blocks count: extracting part of a function into another module is a
    # refactor, not a split, and is proved by the compiler and the goldens.
    dels, texts = [], {}
    for status, path, om, nm in changed_files(repo, p, c):
        if not text_mode(om, nm):
            continue
        old = lines_of(repo, p, path) if status != 'A' else []
        new = lines_of(repo, c, path) if status != 'D' else []
        texts[path] = ('\n' + '\n'.join(old) + '\n', '\n' + '\n'.join(new) + '\n')
        S, codes = states(old)
        runs = [(h[0] - 1, h[0] - 1 + h[1]) for h in hunks(repo, p, c, path) if h[1]]
        prev = 0
        for i, (s, e) in enumerate(runs):
            # Diff placement is ambiguous: slide the run to where it starts at file scope, if it can.
            hi = runs[i + 1][0] if i + 1 < len(runs) else len(old)
            a, b, _ = place(old, S, s, e, prev, hi)
            dels.extend((path, at, block) for at, block in whole_blocks(old, S, codes, a, b))
            prev = b
    # A deleted block has moved when another changed file holds it more often after the commit than
    # before (counting whole files avoids the ambiguous placement of added hunks).
    for path, at, block in dels:
        text = '\n' + '\n'.join(block) + '\n'
        for apath, (before, after) in texts.items():
            if apath != path and after.count(text) > before.count(text):
                raise Fail('%s:%d: %d lines move verbatim to %s; a move is its own "split: " commit'
                           % (path, at, len(block), apath))


def subject_of(repo, c):
    return git(repo, 'log', '-1', '--format=%s', c).decode('utf-8', 'replace').strip()


def kind_of(subject):
    for prefix, kind in PREFIXES:
        if subject.startswith(prefix):
            return kind
    return None


def check(repo, c, kind):
    parents = git(repo, 'rev-list', '--parents', '-n', '1', c).decode().split()[1:]
    if len(parents) != 1:
        raise Fail('a %s commit has exactly one parent' % (kind or 'checked'))
    {'split': check_split, 'header': check_header, 'linkage': check_linkage,
     'unmarked': check_unmarked}[kind](repo, parents[0], c)


def waivers(repo, rev):
    try:
        text = git(repo, 'cat-file', 'blob', '%s:%s' % (rev, WAIVERS)).decode('utf-8', 'replace')
    except RuntimeError:
        return {}
    out = {}
    for ln in text.splitlines():
        ln = ln.split('#', 1)[0].strip()
        if ln:
            sha, _, reason = ln.partition(' ')
            out[sha.lower()] = reason.strip()
    return out


def main():
    ap = argparse.ArgumentParser(description='Move-only checker for the #29 split commits')
    ap.add_argument('--repo', default=os.getcwd())
    ap.add_argument('--range', help='BASE..HEAD: check every marked commit, and unmarked commits for moves')
    ap.add_argument('commits', nargs='*')
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    todo = []
    waived = {}
    if args.range:
        head = args.range.split('..', 1)[1] or 'HEAD'
        waived = waivers(repo, head)
        landed = git(repo, 'log', '--format=%H', '--diff-filter=A', head, '--', SELF).decode().split()
        before = set(git(repo, 'rev-list', landed[-1]).decode().split()) if landed else set()
        for c in git(repo, 'rev-list', '--reverse', '--no-merges', args.range).decode().split():
            kind = kind_of(subject_of(repo, c))
            if kind:
                todo.append((c, kind))
            elif c not in before:
                todo.append((c, 'unmarked'))
    for c in args.commits:
        sha = git(repo, 'rev-parse', '--verify', c + '^{commit}').decode().strip()
        todo.append((sha, kind_of(subject_of(repo, sha)) or 'split'))
    if not todo:
        print('move-only check: no commits to check')
        return 0

    failed = 0
    for c, kind in todo:
        subject = subject_of(repo, c)
        w = next((r for s, r in waived.items() if len(s) >= 7 and c.startswith(s)), None)
        if w is not None:
            print('WAIVED %s %s (%s)' % (c[:10], subject, w))
            continue
        try:
            check(repo, c, kind)
            if kind != 'unmarked':
                print('PASS %s %s' % (c[:10], subject))
        except Fail as e:
            failed += 1
            print('FAIL %s %s\n     %s' % (c[:10], subject, e))
    checked = sum(1 for _, k in todo if k != 'unmarked')
    print('move-only check: %d marked commit(s), %d unmarked commit(s) scanned for moves, %d failure(s)'
          % (checked, len(todo) - checked, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
