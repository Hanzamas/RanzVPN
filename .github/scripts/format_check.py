# Token-stream checker for the one-time reformat (spec #24, pass 11).
#
# The reformat is proven safe by comparing the C token stream of every file before and after
# clang-format. Comments and whitespace are not tokens; everything else is: identifiers,
# keywords, numbers, string and character literals (byte for byte), punctuators, a UTF-8 byte
# order mark, the boundaries of preprocessor directives ('#' at the start of a line opens one,
# '<EOL>' closes it) and the '(' that makes a #define function-like ('<params(>'), since a space
# before it would change the macro. Line continuations are spliced before tokenizing, as the
# compiler does.
#
# Modes:
#   identical BEFORE AFTER   every file must have the same token stream before and after.
#   braces    BEFORE AFTER   the only allowed difference is the deletion of balanced { } pairs that
#                            enclose exactly one statement. A deleted pair must be the body of an
#                            if, else, for, while or do, and not part of a directive (a #define
#                            body); the statement inside must parse as one statement, not a
#                            declaration, whichever #if arm is taken (directives only inside a
#                            nested bracket group, each arm keeping the brackets balanced);
#                            deleting the braces must not let a following 'else' bind to a
#                            different 'if', on any path through the #if groups after the
#                            pair (the first token of every arm, the token after the group
#                            when an arm is empty or there is no #else, and the token after
#                            the #endif when the pair ends an arm). A macro whose expansion is
#                            more than one statement (a ';', an 'if' or an 'else' outside
#                            parentheses and braces, or another such macro there) counts as
#                            such an 'else' in those places, and outside nested { } the
#                            statement must not use one.
#   files                    print the files the reformat applies to, one per line.
#   count ROOT               print line counts of those files per directory as JSON.
#   table NAME=JSON ...      print a markdown table of several 'count' outputs.
#
# Exit status is 0 when every file passes, 1 otherwise. Standard library only.

import argparse
import bisect
import json
import os
import re
import subprocess
import sys

# The reformat scope: Cedar, Mayaqua, the program entry sources, the new core (src/Core) and its
# test program (src/coretest). Third-party code, driver sources that CI does not compile
# (src/SeLow), the test and fuzz programs of the slim fork (src/vpntest, src/fuzz) and generated
# files are excluded.
SCOPE_DIRS = ['src/Cedar', 'src/Mayaqua', 'src/ranz-node', 'src/Core', 'src/coretest']
SCOPE_EXTS = ('.c', '.h', '.cpp')
EXCLUDED_PREFIXES = ['src/Mayaqua/3rdparty/', 'src/Core/3rdparty/']
# Generated files inside SCOPE_DIRS, by path. None are left: the MIDL output (netcfgn.h,
# netcfgx.h) and the resource editor's resource.h files went with the slim-down.
EXCLUDED_FILES = set()

BOM = '\xef\xbb\xbf'  # UTF-8 byte order mark, as decoded with latin-1

_TOKEN_RE = re.compile(r'''
  (?P<nl>\n)
| (?P<ws>[ \t\f\v\r]+)
| (?P<lc>//[^\n]*)
| (?P<bc>/\*.*?\*/)
| (?P<bcu>/\*.*)
| (?P<raw>(?:u8|[uUL])?R"(?P<delim>[^ ()\\\t\v\f\n"]{0,16})\(.*?\)(?P=delim)")
| (?P<str>(?:u8|[uUL])?"(?:[^"\\\n]|\\.)*(?:"|(?=\n)|\Z))
| (?P<chr>(?:u8|[uUL])?'(?:[^'\\\n]|\\.)*(?:'|(?=\n)|\Z))
| (?P<num>\.?[0-9](?:[eEpP][+-]|[0-9A-Za-z_.]|'(?=[0-9A-Za-z]))*)
| (?P<id>[A-Za-z_$\x80-\xff][A-Za-z0-9_$\x80-\xff]*)
| (?P<punct>\.\.\.|<<=|>>=|->\*|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\*=|/=|%=|\+=|-=|&=|\^=|\|=|\#\#|::|\.\*|.)
''', re.S | re.X)

_HEADER_NAME_RE = re.compile(r'[ \t]*(<[^>\n]*>)')
_DIRECTIVE_NAME_RE = re.compile(r'[ \t]*(?:/\*.*?\*/[ \t]*)*([A-Za-z_]+)', re.S)
_MACRO_NAME_RE = re.compile(r'[ \t]*(?:/\*.*?\*/[ \t]*)*([A-Za-z_$][A-Za-z0-9_$]*)(\()?', re.S)
_INCLUDE_WORDS = {'include', 'include_next', 'import'}


class Tokens:
    """Token list of one file, with the 1-based source line of each token."""

    def __init__(self, toks, lines):
        self.toks = toks
        self.lines = lines

    def __len__(self):
        return len(self.toks)


def _splice(text):
    """Remove backslash-newline pairs. Returns the spliced text and, for error messages, the
    spliced offsets where a splice was removed."""
    parts = text.split('\\\n')
    if len(parts) == 1:
        return text, []
    offsets = []
    pos = 0
    for part in parts[:-1]:
        pos += len(part)
        offsets.append(pos)
    return ''.join(parts), offsets


def tokenize(data):
    """Tokenize C or C++ source bytes. Comments and whitespace are dropped."""
    text = data.decode('latin-1')
    toks = []
    lines = []
    if text.startswith(BOM):
        toks.append('<BOM>')
        lines.append(1)
        text = text[len(BOM):]
    text = text.replace('\r\n', '\n')
    text, splices = _splice(text)
    newlines = [m.start() for m in re.finditer('\n', text)]

    def line_of(pos):
        return bisect.bisect_left(newlines, pos) + bisect.bisect_right(splices, pos) + 1

    pos = 0
    n = len(text)
    bol = True          # only whitespace and comments so far on this line
    directive = False   # inside a preprocessor directive
    want_header = False  # right after '#include'
    while pos < n:
        if want_header:
            want_header = False
            m = _HEADER_NAME_RE.match(text, pos)
            if m:
                toks.append(m.group(1))
                lines.append(line_of(m.start(1)))
                pos = m.end()
                continue
        m = _TOKEN_RE.match(text, pos)
        kind = m.lastgroup
        if kind == 'delim':
            kind = 'raw'
        start = pos
        pos = m.end()
        if kind == 'nl':
            if directive:
                toks.append('<EOL>')
                lines.append(line_of(start))
                directive = False
            bol = True
            continue
        if kind in ('ws', 'lc', 'bc'):
            continue
        if kind == 'bcu':
            toks.append('<UNTERMINATED-COMMENT>')
            lines.append(line_of(start))
            continue
        tok = m.group(0)
        if tok == '#' and bol and not directive:
            directive = True
            toks.append('#')
            lines.append(line_of(start))
            bol = False
            m2 = _DIRECTIVE_NAME_RE.match(text, pos)
            if m2 and m2.group(1) in _INCLUDE_WORDS:
                # '#include <...>' takes a header name, which is not tokenized further
                toks.append(m2.group(1))
                lines.append(line_of(m2.start(1)))
                pos = m2.end()
                want_header = True
            elif m2 and m2.group(1) == 'define':
                # a '(' right after the macro name makes it function-like; a space there would
                # make it object-like, so that '(' is a token of its own kind
                toks.append('define')
                lines.append(line_of(m2.start(1)))
                pos = m2.end()
                m3 = _MACRO_NAME_RE.match(text, pos)
                if m3:
                    toks.append(m3.group(1))
                    lines.append(line_of(m3.start(1)))
                    pos = m3.end()
                    if m3.group(2):
                        toks.append('<params(>')
                        lines.append(line_of(m3.start(2)))
            continue
        bol = False
        toks.append(tok)
        lines.append(line_of(start))
    if directive:
        toks.append('<EOL>')
        lines.append(line_of(n))
    return Tokens(toks, lines)


# ---------------------------------------------------------------------------------------------
# Statement parser for the braces mode. It works on a list of token strings and accepts a
# conservative subset of C: anything it does not understand is "not one statement".

class NotAStatement(Exception):
    pass


_COMPOUND_KEYWORDS = {'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default'}
_JUMP_KEYWORDS = {'return', 'goto', 'break', 'continue'}
_OPEN = {'(': ')', '[': ']', '{': '}'}
_CLOSE = {')', ']', '}'}
_IDENT_RE = re.compile(r'[A-Za-z_$\x80-\xff][A-Za-z0-9_$\x80-\xff]*$')

# A declaration is not a statement in C, so braces around one must stay. Its first token is one
# of these, or it has the shape 'name name' / 'name * name' (see _looks_like_declaration).
_QUALIFIERS = {'const', 'volatile', 'restrict', '__restrict', '_Atomic'}
_DECLARATION_KEYWORDS = _QUALIFIERS | {
    'auto', 'register', 'static', 'extern', 'typedef', '_Thread_local', 'thread_local',
    'inline', '__inline', '__forceinline', 'constexpr', 'struct', 'union', 'enum', 'class',
    'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned', '_Bool',
    'bool', '_Complex', 'wchar_t', '__int8', '__int16', '__int32', '__int64', 'typeof',
    '__typeof__', '_Alignas', 'alignas', '__declspec', '__attribute__', '_Static_assert',
    'static_assert', 'using', 'namespace', 'template', 'typename'}
# Keywords that start an expression or a statement and are followed by a name.
_NOT_A_TYPE = _COMPOUND_KEYWORDS | _JUMP_KEYWORDS | {
    'sizeof', '_Alignof', 'alignof', 'defined', 'new', 'delete', 'throw'}
_DECLARATOR_FOLLOWERS = {'=', ';', '[', ',', '('}


def _skip_directive(v, i):
    """v[i] is the '#' of a directive; return the index after its '<EOL>'."""
    while i < len(v) and v[i] != '<EOL>':
        i += 1
    return i + 1


def _skip_group(v, k):
    """v[k] is an opening bracket; return the index after its matching closing bracket.
    Directives inside the group are skipped here; conditional_arms_balanced() decides whether
    they are acceptable."""
    stack = []
    i = k
    while i < len(v):
        t = v[i]
        if t == '#':
            i = _skip_directive(v, i)
            continue
        if t == '<EOL>':
            raise NotAStatement('stray end of directive')
        if t in _OPEN:
            stack.append(_OPEN[t])
        elif t in _CLOSE:
            if not stack or stack.pop() != t:
                raise NotAStatement('unbalanced brackets')
            if not stack:
                return i + 1
        i += 1
    raise NotAStatement('unterminated bracket')


def _expect(v, k, tok):
    if k >= len(v) or v[k] != tok:
        raise NotAStatement('expected %r' % tok)


def _looks_like_declaration(v, k):
    """v[k:] starts like a declaration: a storage class, qualifier, struct/union/enum or type
    keyword, or a name followed by '*'s and qualifiers, then a second name and one of
    = ; [ , ( ('UINT x = 1;', 'UCHAR *p;', 'BOOL f(void);'). No expression starts with two
    names, and 'a * b;' or 'a * f(x);' do nothing as statements, so this is conservative."""
    t = v[k]
    if t in _DECLARATION_KEYWORDS:
        return True
    if not _IDENT_RE.match(t) or t in _NOT_A_TYPE:
        return False
    i = k + 1
    while i < len(v) and (v[i] in ('*', '&') or v[i] in _QUALIFIERS):
        i += 1
    return (i + 1 < len(v) and _IDENT_RE.match(v[i]) is not None and v[i] not in _NOT_A_TYPE
            and v[i + 1] in _DECLARATOR_FOLLOWERS)


def parse_statement(v, k):
    """Parse one statement of v starting at k. Returns (end, open_if): the index after the
    statement and whether it ends in an 'if' without 'else' (a following 'else' would bind to
    it)."""
    if k >= len(v):
        raise NotAStatement('no statement')
    t = v[k]
    if t == '{':
        return _skip_group(v, k), False
    if t == ';':
        return k + 1, False
    if t == 'if':
        _expect(v, k + 1, '(')
        end, open_if = parse_statement(v, _skip_group(v, k + 1))
        if end < len(v) and v[end] == 'else':
            return parse_statement(v, end + 1)
        return end, True
    if t in ('while', 'for'):
        _expect(v, k + 1, '(')
        return parse_statement(v, _skip_group(v, k + 1))
    if t == 'do':
        end, _ = parse_statement(v, k + 1)
        _expect(v, end, 'while')
        _expect(v, end + 1, '(')
        end = _skip_group(v, end + 1)
        _expect(v, end, ';')
        return end + 1, False
    if t in ('else', 'switch', 'case', 'default', '#', '<EOL>') or t in _CLOSE:
        raise NotAStatement('unsupported statement start %r' % t)
    if k + 1 < len(v) and v[k + 1] == ':' and re.match(r'[A-Za-z_]\w*$', t):
        raise NotAStatement('labelled statement')
    if _looks_like_declaration(v, k):
        raise NotAStatement('a declaration')
    # Expression statement or a jump statement: everything up to ';' outside brackets.
    i = k
    while i < len(v):
        t = v[i]
        if t == ';':
            return i + 1, False
        if t in _OPEN:
            i = _skip_group(v, i)
            continue
        if t in _CLOSE or t in ('#', '<EOL>') or t in _COMPOUND_KEYWORDS:
            raise NotAStatement('unexpected %r' % t)
        if t in _JUMP_KEYWORDS and i != k:
            raise NotAStatement('unexpected %r' % t)
        i += 1
    raise NotAStatement('missing ;')


_IF_DIRECTIVES = {'if', 'ifdef', 'ifndef'}
_ARM_DIRECTIVES = {'elif', 'else', 'elifdef', 'elifndef'}


def _directive_name(v, i):
    """v[i] is the '#' of a directive; return its name ('' when there is none)."""
    return v[i + 1] if i + 1 < len(v) else ''


def _conditional_arms(v, i):
    """v[i] is the '#' of an #if, #ifdef or #ifndef. Return (starts, has_else, end): the index
    after the directive line that opens each arm (the #if, every #elif and the #else), whether
    the group has an #else, and the index after its #endif (len(v) when it is missing)."""
    starts = []
    has_else = False
    depth = 0
    k = i
    while k < len(v):
        if v[k] != '#':
            k += 1
            continue
        name = _directive_name(v, k)
        nxt = _skip_directive(v, k)
        if name in _IF_DIRECTIVES:
            depth += 1
            if depth == 1:
                starts.append(nxt)
        elif name in _ARM_DIRECTIVES:
            if depth == 1:
                starts.append(nxt)
                has_else = has_else or name == 'else'
        elif name == 'endif':
            depth -= 1
            if depth == 0:
                return starts, has_else, nxt
        k = nxt
    return starts, has_else, len(v)


def _skip_to_endif(v, k):
    """v[k] is the '#' of an #elif or #else, reached at the end of the arm before it; return the
    index after the #endif of that group, where the compiler goes on (len(v) when missing)."""
    depth = 0
    while k < len(v):
        if v[k] != '#':
            k += 1
            continue
        name = _directive_name(v, k)
        nxt = _skip_directive(v, k)
        if name in _IF_DIRECTIVES:
            depth += 1
        elif name == 'endif':
            if depth == 0:
                return nxt
            depth -= 1
        k = nxt
    return len(v)


def following_tokens(v, k, skip=frozenset()):
    """The tokens that can come right after v[k] once the indices in skip are gone, on every
    path the compiler can take through the #if groups that follow. An #if group leads to the
    first token of each of its arms, and to the token after the group when an arm is empty or
    there is no #else; an #elif or #else reached from inside an arm ends it, so the path goes on
    after the #endif; other directives are skipped. None stands for the end of the tokens."""
    out = set()
    todo = [k + 1]
    groups = set()
    while todo:
        i = todo.pop()
        while i < len(v) and (i in skip or v[i] == '#'):
            if i in skip:
                i += 1
                continue
            name = _directive_name(v, i)
            if name in _IF_DIRECTIVES:
                break
            if name in _ARM_DIRECTIVES:
                i = _skip_to_endif(v, i)
            else:
                i = _skip_directive(v, i)
        if i >= len(v):
            out.add(None)
        elif v[i] != '#':
            out.add(v[i])
        elif i not in groups:
            groups.add(i)
            starts, has_else, end = _conditional_arms(v, i)
            todo.extend(starts if has_else else starts + [end])
    return out


def conditional_arms_balanced(v):
    """Every #if group in v starts and ends in v, and each of its arms closes exactly the
    brackets it opens: at every #elif, #else and #endif the open brackets are the very ones
    that were open at the #if. Then the statement structure around the group is the same
    whichever arm the compiler takes."""
    open_brackets = []
    starts = []
    i = 0
    while i < len(v):
        t = v[i]
        if t == '#':
            name = _directive_name(v, i)
            if name in _IF_DIRECTIVES:
                starts.append(tuple(open_brackets))
            elif name in _ARM_DIRECTIVES:
                if not starts or starts[-1] != tuple(open_brackets):
                    return False
            elif name == 'endif':
                if not starts or starts.pop() != tuple(open_brackets):
                    return False
            i = _skip_directive(v, i)
            continue
        if t in _OPEN:
            open_brackets.append(i)
        elif t in _CLOSE:
            if not open_brackets:
                return False
            open_brackets.pop()
        i += 1
    return not starts


def directive_indices(v):
    """Indices of the tokens of v that belong to a preprocessor directive, '#' to '<EOL>'."""
    out = set()
    i = 0
    while i < len(v):
        if v[i] == '#':
            end = _skip_directive(v, i)
            out.update(range(i, end))
            i = end
        else:
            i += 1
    return out


def top_level_tokens(v):
    """Tokens of v outside nested { } groups and outside directives."""
    out = []
    depth = 0
    i = 0
    while i < len(v):
        t = v[i]
        if t == '#':
            i = _skip_directive(v, i)
            continue
        if t == '{':
            depth += 1
        elif t == '}':
            depth -= 1
        elif depth == 0:
            out.append(t)
        i += 1
    return out


def one_statement(v):
    """Return open_if when v is exactly one statement, else raise NotAStatement."""
    end, open_if = parse_statement(v, 0)
    if end != len(v):
        raise NotAStatement('more than one statement')
    return open_if


def match_brackets(toks):
    """Map each bracket index to its partner, for (), [] and {} separately nested. Brackets
    left unmatched (for example by #if branches) have no entry."""
    match = {}
    stacks = {'(': [], '[': [], '{': []}
    closers = {')': '(', ']': '[', '}': '{'}
    for i, t in enumerate(toks):
        if t == '<params(>':
            t = '('
        if t in stacks:
            stacks[t].append(i)
        elif t in closers:
            s = stacks[closers[t]]
            if s:
                j = s.pop()
                match[i] = j
                match[j] = i
    return match


def unsafe_macros(token_lists):
    """Names of macros whose expansion is more than one statement or starts an 'if': a ';', an
    'if' or an 'else' outside parentheses, brackets and braces, unless the whole body is
    do { ... } while (0). A macro whose body uses such a macro outside parentheses, brackets and
    braces is one too, since its expansion holds the same tokens. A '(' right after the name is
    read as the parameter list; for an object-like macro whose body starts with '(' that skips
    a group where nothing is flagged anyway."""
    bodies = []
    for toks in token_lists:
        i = 0
        while i + 2 < len(toks):
            if toks[i] != '#' or toks[i + 1] != 'define':
                i += 1
                continue
            name = toks[i + 2]
            end = toks.index('<EOL>', i)
            k = i + 3
            if k < end and toks[k] == '<params(>':
                while k < end and toks[k] != ')':
                    k += 1
                k += 1
            body = toks[k:end]
            i = end + 1
            if len(body) >= 6 and body[0] == 'do' and body[-4:] == ['while', '(', '0', ')']:
                continue
            depth = 0
            top = set()
            for t in body:
                if t in _OPEN:
                    depth += 1
                elif t in _CLOSE:
                    depth -= 1
                elif depth == 0:
                    top.add(t)
            bodies.append((name, top))
    names = set()
    changed = True
    while changed:
        changed = False
        for name, top in bodies:
            if name not in names and (top & {';', 'if', 'else'} or top & names):
                names.add(name)
                changed = True
    return names


def _brace_position_ok(a, match, o):
    """The '{' at a[o] opens the body of an if, else, for, while or do."""
    if o == 0:
        return False
    p = a[o - 1]
    if p in ('else', 'do'):
        return True
    if p == ')' and (o - 1) in match:
        q = match[o - 1]
        return q > 0 and a[q - 1] in ('if', 'for', 'while')
    return False


def check_braces(a, b, macros):
    """Return (removed_pairs, error). a and b are token lists."""
    match = match_brackets(a)
    deleted = set()
    pending = set()
    i = j = 0
    while i < len(a):
        if i in pending:
            deleted.add(i)
            i += 1
            continue
        if j < len(b) and a[i] == b[j]:
            i += 1
            j += 1
            continue
        if a[i] == '{' and i in match:
            deleted.add(i)
            pending.add(match[i])
            i += 1
            continue
        return None, (i, j, 'token differs and is not a deletable "{"')
    if j != len(b):
        return None, (i, j, 'extra tokens after the end of the original')

    in_directive = directive_indices(a)

    def pair_error(o, c):
        # a pair in a #define body would have to hold at every use site of the macro, which
        # this check does not see (an 'else' after the use could bind to a different 'if')
        if o in in_directive or c in in_directive:
            return 'the braces are inside a preprocessor directive'
        if not _brace_position_ok(a, match, o):
            return 'the braces are not the body of if, else, for, while or do'
        content = a[o + 1:c]
        kept = [a[k] for k in range(o + 1, c) if k not in deleted]
        try:
            one_statement(content)
            open_if = one_statement(kept)
        except NotAStatement as e:
            return 'the braces do not enclose exactly one statement (%s)' % e
        if '#' in content and not conditional_arms_balanced(content):
            return 'a preprocessor conditional inside does not keep the brackets balanced'
        # an 'else' that can follow the pair, in any #if arm or after one, binds to the inner
        # 'if' once the braces go; so may a macro there that expands to more than one
        # statement, as its expansion can start with 'else'
        if open_if:
            following = following_tokens(a, c, deleted)
            if 'else' in following:
                return 'a following else would bind to a different if'
            used = macros.intersection(following)
            if used:
                return 'a following macro may expand to an else that would bind to a ' \
                       'different if: %s' % ', '.join(sorted(used))
        # a macro inside a nested { } that stays is harmless; one outside it is not
        used = macros.intersection(top_level_tokens(kept))
        if used:
            return 'the statement uses a multi-statement macro: %s' % ', '.join(sorted(used))
        return None

    pairs = sorted((o, match[o]) for o in deleted if a[o] == '{')
    for o, c in pairs:
        err = pair_error(o, c)
        # Equivalent reading: deleting the inner of two directly nested pairs leaves the same
        # tokens as deleting the outer one, so try the enclosing pairs before failing.
        oo, cc = o, c
        while err is not None and oo > 0 and a[oo - 1] == '{' and match.get(oo - 1) == cc + 1 \
                and (oo - 1) not in deleted and (cc + 1) not in deleted:
            deleted.difference_update((oo, cc))
            oo, cc = oo - 1, cc + 1
            deleted.update((oo, cc))
            err = pair_error(oo, cc)
        if err is not None:
            return None, (o, None, err)
    return len(pairs), None


# ---------------------------------------------------------------------------------------------

def scoped_files(root):
    out = subprocess.run(['git', 'ls-files', '-z', '--'] + SCOPE_DIRS, cwd=root,
                         stdout=subprocess.PIPE, check=True).stdout
    files = []
    for name in out.decode('utf-8').split('\0'):
        if not name or not name.endswith(SCOPE_EXTS):
            continue
        if name in EXCLUDED_FILES or any(name.startswith(p) for p in EXCLUDED_PREFIXES):
            continue
        files.append(name)
    return sorted(files)


def _read(path):
    with open(path, 'rb') as f:
        return f.read()


def _context(tokens, k, width=8):
    lo = max(0, k - width)
    return ' '.join(tokens.toks[lo:k]) + ' >>> ' + ' '.join(tokens.toks[k:k + width])


def _line(tokens, k):
    if k is None:
        return '?'
    if k < len(tokens.lines):
        return tokens.lines[k]
    return 'EOF'


def run_compare(mode, before, after, files):
    macros = set()
    if mode == 'braces':
        macros = unsafe_macros(tokenize(_read(os.path.join(before, f))).toks for f in files)
        print('macros treated as multi-statement: %d' % len(macros))
    failed = 0
    removed_total = 0
    for f in files:
        ta = tokenize(_read(os.path.join(before, f)))
        tb = tokenize(_read(os.path.join(after, f)))
        if mode == 'identical':
            if ta.toks == tb.toks:
                continue
            k = 0
            while k < min(len(ta), len(tb)) and ta.toks[k] == tb.toks[k]:
                k += 1
            failed += 1
            print('FAIL %s: token %d differs (before line %s, after line %s)'
                  % (f, k, _line(ta, k), _line(tb, k)))
            print('  before: ' + _context(ta, k))
            print('  after:  ' + _context(tb, k))
        else:
            removed, err = check_braces(ta.toks, tb.toks, macros)
            if err is None:
                removed_total += removed
                if removed:
                    print('ok   %s: %d brace pairs removed' % (f, removed))
                continue
            i, j, why = err
            failed += 1
            print('FAIL %s: %s (before line %s, after line %s)'
                  % (f, why, _line(ta, i), _line(tb, j)))
            print('  before: ' + _context(ta, i))
            if j is not None:
                print('  after:  ' + _context(tb, j))
    print('%s: %d files checked, %d failed%s'
          % (mode, len(files), failed,
             ', %d brace pairs removed' % removed_total if mode == 'braces' else ''))
    return 1 if failed else 0


def count_lines(root, files):
    counts = {}
    for f in files:
        data = _read(os.path.join(root, f))
        n = data.count(b'\n') + (1 if data and not data.endswith(b'\n') else 0)
        d = next(s for s in SCOPE_DIRS if f.startswith(s + '/'))
        counts[d] = counts.get(d, 0) + n
    counts['total'] = sum(counts.values())
    return counts


def table(columns):
    names = [n for n, _ in columns]
    data = [c for _, c in columns]
    keys = [d for d in SCOPE_DIRS if any(d in c for c in data)] + ['total']
    out = ['| directory | ' + ' | '.join(names) + ' | change |',
           '|---|' + '---:|' * (len(names) + 1)]
    for k in keys:
        vals = [c.get(k, 0) for c in data]
        out.append('| %s | %s | %+d |' % (k, ' | '.join('{:,}'.format(v) for v in vals),
                                          vals[-1] - vals[0]))
    return '\n'.join(out)


def main(argv):
    ap = argparse.ArgumentParser(description='Token-stream checker for the reformat (spec #24).')
    sub = ap.add_subparsers(dest='cmd', required=True)
    for mode in ('identical', 'braces'):
        p = sub.add_parser(mode)
        p.add_argument('before')
        p.add_argument('after')
        p.add_argument('--files-from', help='file list (default: the reformat scope of AFTER)')
    sub.add_parser('files').add_argument('root', nargs='?', default='.')
    sub.add_parser('count').add_argument('root', nargs='?', default='.')
    sub.add_parser('table').add_argument('columns', nargs='+', help='NAME=count.json')
    args = ap.parse_args(argv)

    if args.cmd == 'files':
        print('\n'.join(scoped_files(args.root)))
        return 0
    if args.cmd == 'count':
        print(json.dumps(count_lines(args.root, scoped_files(args.root)), indent=1))
        return 0
    if args.cmd == 'table':
        cols = []
        for c in args.columns:
            name, path = c.split('=', 1)
            with open(path) as f:
                cols.append((name, json.load(f)))
        print(table(cols))
        return 0
    if args.files_from:
        with open(args.files_from) as f:
            files = [x.strip() for x in f if x.strip()]
    else:
        files = scoped_files(args.after)
    return run_compare(args.cmd, args.before, args.after, files)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
