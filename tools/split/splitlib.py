"""Top-level parser for the C sources of Ranz VPN, shared by apply_split.py and check_moves.py.

A C file is cut into top-level items: function definitions, prototypes, file-scope data,
types, preprocessor directives and conditional regions (#if ... #endif at file scope, kept
whole). Each item spans whole lines and carries the comment block written directly above it
(no blank line between). Text between items (blank lines, detached comments) is a gap.

Files are read and written as latin-1, so every byte round-trips unchanged (CRLF, UTF-8 text).
"""
import os
import re

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FNPTR = re.compile(r"\(\s*(?:[A-Za-z_]\w*\s+)*\*+\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?\)\s*\(")


def fnptr(s):
    """The name declared by a function-pointer declarator '(*name)(...)', when the first '(' of s opens one."""
    m = FNPTR.search(s)
    if m and m.start() == s.find("("):
        return m
    return None


DIRECTIVE = re.compile(r"\s*#\s*([A-Za-z_]+)")
C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "__inline", "__forceinline", "__declspec", "__cdecl", "__stdcall",
}


class ParseError(Exception):
    pass


# File-scope macros that define a function: macro name -> index of the argument that names it.
# Filled from the split map ("macro_defines"), e.g. DECLARE_SC("GetServerInfo", T, ScGetServerInfo, ...).
MACRO_DEFS = {}


def read_text(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1")


def write_text(path, text):
    with open(path, "wb") as f:
        f.write(text.encode("latin-1"))


def mask(text):
    """Same-length copy of text: comments and the inside of string and char literals become spaces.
    Newlines stay, so offsets and line numbers match the original."""
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c == '"' or c == "'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                if text[j] == "\\" and j + 1 < n and text[j + 1] != "\n":
                    j += 1
                j += 1
            for k in range(i + 1, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


class Item:
    """One top-level unit. l0..l1 are 0-based inclusive line numbers including the attached
    comment; cl is the first code line."""

    def __init__(self, kind, l0, cl, l1):
        self.kind = kind
        self.l0, self.cl, self.l1 = l0, cl, l1
        self.names = []
        self.static = False
        self.refs = set()
        self.branches = []  # cond: list of (directive line no, [items])
        self.directive = None
        self.text = ""
        self.code = ""

    def all_names(self):
        if self.kind != "cond":
            return list(self.names)
        out = []
        for _, items in self.branches:
            for it in items:
                out.extend(it.all_names())
        return out

    def __repr__(self):
        return f"<{self.kind} {self.names[:3]} L{self.l0 + 1}-{self.l1 + 1}>"


class CFile:
    def __init__(self, path=None, text=None):
        self.path = path
        self.text = read_text(path) if text is None else text
        self.code = mask(self.text)
        self.lines = self.text.split("\n")
        self.clines = self.code.split("\n")
        self.starts = []
        off = 0
        for ln in self.lines:
            self.starts.append(off)
            off += len(ln) + 1
        self.items = self._seg(0, len(self.lines))
        self.guard = None  # (open item lines, close line) when the whole file is one #if region
        self._unwrap_guard()
        for it in self.walk():
            self._fill(it)

    # ---- line helpers
    def ltext(self, i, j):
        """Text of lines i..j inclusive, with the final newline when the file has one."""
        a = self.starts[i]
        b = self.starts[j + 1] if j + 1 < len(self.starts) else len(self.text)
        return self.text[a:b]

    def lcode(self, i, j):
        a = self.starts[i]
        b = self.starts[j + 1] if j + 1 < len(self.starts) else len(self.text)
        return self.code[a:b]

    def line_of(self, off):
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _directive(self, i):
        m = DIRECTIVE.match(self.clines[i])
        return m.group(1) if m else None

    def _dir_end(self, i):
        j = i
        while j + 1 < len(self.lines) and self.clines[j].rstrip().endswith("\\"):
            j += 1
        return j

    def _match_endif(self, i, hi):
        depth = 0
        branches = [i]
        j = i
        while j < hi:
            d = self._directive(j)
            if d in ("if", "ifdef", "ifndef"):
                depth += 1
            elif d in ("elif", "else") and depth == 1:
                branches.append(j)
            elif d == "endif":
                depth -= 1
                if depth == 0:
                    return j, branches
            j = self._dir_end(j) + 1 if d else j + 1
        raise ParseError(f"{self.path}:{i + 1}: #{self._directive(i)} without #endif")

    def _seg(self, lo, hi):
        items = []
        i = lo
        pend = None
        while i < hi:
            t = self.lines[i]
            c = self.clines[i].strip()
            if t.strip() == "":
                pend = None
                i += 1
                continue
            if c == "":
                if pend is None:
                    pend = i
                i += 1
                continue
            start = pend if pend is not None else i
            pend = None
            if c.startswith("#"):
                d = self._directive(i)
                if d in ("if", "ifdef", "ifndef"):
                    j, br = self._match_endif(i, hi)
                    it = Item("cond", start, i, j)
                    br = br + [j]
                    for k in range(len(br) - 1):
                        a = self._dir_end(br[k]) + 1
                        it.branches.append((br[k], self._seg(a, br[k + 1])))
                    it.directive = d
                    items.append(it)
                    i = j + 1
                    continue
                if d in ("else", "elif", "endif"):
                    raise ParseError(f"{self.path}:{i + 1}: stray #{d}")
                j = self._dir_end(i)
                kind = {"define": "macro", "include": "include", "undef": "undef", "pragma": "pragma"}.get(d, "directive")
                it = Item(kind, start, i, j)
                it.directive = d
                items.append(it)
                i = j + 1
                continue
            end = self._scan_decl(self.starts[i], i, hi)
            j = self.line_of(end - 1) if end > 0 else i
            # merge anything else that starts on the same line
            while True:
                rest = self.code[end:self.starts[j + 1] - 1] if j + 1 < len(self.starts) else self.code[end:]
                if rest.strip() == "":
                    break
                end = self._scan_decl(end, j, hi)
                j = self.line_of(end - 1)
            it = Item("decl", start, i, j)
            items.append(it)
            i = j + 1
        return items

    def _scan_decl(self, off, line, hi):
        code = self.code
        n = len(code)
        paren = brace = 0
        k = off
        head_start = off
        limit = self.starts[hi] if hi < len(self.starts) else n
        while k < limit:
            ch = code[k]
            if ch == "\n":
                # a directive line inside a declaration or body is part of it
                nl = self.line_of(k + 1) if k + 1 < n else None
                if nl is not None and self.clines[nl].lstrip().startswith("#"):
                    e = self._dir_end(nl)
                    k = self.starts[e + 1] - 1 if e + 1 < len(self.starts) else n
                    continue
            elif ch in "([":
                paren += 1
            elif ch in ")]":
                paren -= 1
                if paren == 0 and brace == 0 and ch == ")" and self._is_macro_call_line(head_start, k):
                    return k + 1
            elif ch == "{":
                if brace == 0 and paren == 0 and _is_function_head(code[head_start:k]):
                    return self._func_end(k, line)
                brace += 1
            elif ch == "}":
                brace -= 1
            elif ch == ";" and brace == 0 and paren == 0:
                return k + 1
            k += 1
        raise ParseError(f"{self.path}:{line + 1}: declaration does not end")

    def _is_macro_call_line(self, a, k):
        """A file-scope macro invocation without a semicolon, such as
        DECLARE_SC("GetServerInfo", RPC_SERVER_INFO, ScGetServerInfo, ...): one name, its
        argument list, and nothing after it on the line nor a body on the next line."""
        head = self.code[a:k + 1].strip()
        if not re.fullmatch(r"[A-Za-z_]\w*\s*\(.*\)", head, re.S):
            return False
        ln = self.line_of(k)
        rest = self.code[k + 1:self.starts[ln + 1] if ln + 1 < len(self.starts) else len(self.code)]
        if rest.strip() != "":
            return False
        for m in range(ln + 1, len(self.lines)):
            c = self.clines[m].strip()
            if c:
                return not (c.startswith("{") or c.startswith(";"))
        return True

    def _func_end(self, k, line):
        """Offset just past the closing brace of the body that opens at k. Brace counting, checked
        against the house style: the closing brace of a function body is a lone '}' at column 0."""
        code = self.code
        depth = 0
        n = len(code)
        j = k
        counted = None
        while j < n:
            ch = code[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    counted = j + 1
                    break
            j += 1
        # column-0 rule: the first lone '}' after the line that opens the body
        bl = self.line_of(k)
        styled = None
        for m in range(bl + 1, len(self.lines)):
            if self.clines[m].rstrip() == "}":
                styled = self.starts[m] + 1
                break
        if counted is None and styled is None:
            raise ParseError(f"{self.path}:{line + 1}: function body does not end")
        if counted is not None and self.line_of(counted - 1) == bl:
            return counted  # body on one line
        if counted != styled:
            # trust the column-0 brace when counting is thrown off by #if branches; refuse otherwise
            if styled is not None and counted is not None and self.line_of(counted - 1) == self.line_of(styled - 1):
                return counted
            raise ParseError(
                f"{self.path}:{line + 1}: brace count (line {self.line_of(counted - 1) + 1 if counted else '?'}) "
                f"and column-0 '}}' (line {self.line_of(styled - 1) + 1 if styled else '?'}) disagree")
        return counted

    def _unwrap_guard(self):
        """When the whole file is one #if/#ifndef region with no #else (a header include guard, or
        Microsoft.c's #ifdef OS_WIN32), its body becomes the top level."""
        conds = [it for it in self.items if it.kind == "cond"]
        others = [it for it in self.items if it.kind != "cond"]
        if len(conds) == 1 and not others and len(conds[0].branches) == 1:
            g = conds[0]
            body = g.branches[0][1]
            self.guard = g
            self.items = body

    def walk(self, items=None):
        for it in (self.items if items is None else items):
            yield it
            if it.kind == "cond":
                for _, sub in it.branches:
                    yield from self.walk(sub)

    def _fill(self, it):
        it.text = self.ltext(it.l0, it.l1)
        it.code = self.lcode(it.cl, it.l1)
        it.refs = refs_of(it.code)
        if it.kind == "decl":
            _classify(it)
        elif it.kind == "macro":
            m = re.match(r"\s*#\s*define\s+([A-Za-z_]\w*)", it.code)
            if m:
                it.names = [m.group(1)]
                it.refs.discard(m.group(1))
            it.refs.discard("define")
        elif it.kind == "undef":
            m = re.match(r"\s*#\s*undef\s+([A-Za-z_]\w*)", it.code)
            it.names = []
        elif it.kind == "cond":
            pass

    # ---- prologue: the leading comments, includes and include-only conditionals
    def prologue_end(self):
        """Index into self.items of the first item after the prologue."""
        last_inc = -1
        for idx, it in enumerate(self.items):
            if it.kind == "include":
                last_inc = idx
            elif it.kind == "cond":
                inner = list(self.walk(it.branches[0][1] if len(it.branches) == 1 else
                                       [x for _, b in it.branches for x in b]))
                # a conditional that holds includes is copied whole, so a new file sees the same headers
                if any(x.kind == "include" for x in inner):
                    last_inc = idx
                else:
                    break
            elif it.kind in ("macro", "pragma", "directive", "undef"):
                continue
            else:
                break
        return last_inc + 1

    def prologue_lines(self):
        """Line index just past the prologue (exclusive end)."""
        pe = self.prologue_end()
        if pe == 0:
            return self.guard.cl + 1 if self.guard else 0
        return self.items[pe - 1].l1 + 1

    def epilogue_line(self):
        """Line index where the file's tail begins (the guard's #endif), or len(lines)."""
        if self.guard:
            return self.guard.l1
        return len(self.lines)


def _is_function_head(head):
    h = head.strip()
    if not h.endswith(")"):
        return False
    m = IDENT.match(h)
    if not m or m.group(0) == "typedef":
        return False
    depth = 0
    for ch in h:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "=" and depth == 0:
            return False
    # at least two tokens before the parameter list (a type and a name): a lone MACRO(x) is not a head
    pre = h[:h.index("(")]
    return len(IDENT.findall(pre)) >= 2 or "*" in pre


def refs_of(code):
    out = set()
    for m in IDENT.finditer(code):
        a = m.start()
        b = a - 1
        while b >= 0 and code[b] in " \t\r\n":
            b -= 1
        if b >= 0 and (code[b] == "." or (code[b] == ">" and b > 0 and code[b - 1] == "-")):
            continue
        out.add(m.group(0))
    return out - C_KEYWORDS


def _top_split(s, seps):
    """Split s at top-level characters in seps; returns pieces."""
    out, cur, depth = [], [], 0
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and ch in seps:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _declarator_name(d):
    d = _top_split(d, "=")[0]
    m = fnptr(d)
    if m:
        return m.group(1)
    d = re.sub(r"\[[^\]]*\]", "", d)
    ids = [x for x in IDENT.findall(d) if x not in C_KEYWORDS]
    return ids[-1] if ids else None


def _classify(it):
    s = it.code.strip()
    toks = IDENT.findall(s)
    it.static = "static" in toks[:4]
    first = toks[0] if toks else ""
    # function definition: ends with the body brace
    body = s.find("{")
    if s.rstrip().endswith("}") and body >= 0 and _is_function_head(s[:body]):
        it.kind = "func"
        pre = s[:s.index("(")]
        ids = IDENT.findall(pre)
        it.names = [ids[-1]]
        it.refs.discard(ids[-1])
        return
    s1 = s.rstrip(";").strip()
    if first == "typedef":
        it.kind = "type"
        names = []
        if "{" in s1:
            tag = re.match(r"typedef\s+(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{", s1)
            if tag:
                names.append(tag.group(1))
            if re.match(r"typedef\s+enum\b", s1):
                names += _enum_consts(s1)
            close = s1.rfind("}")
            for d in _top_split(s1[close + 1:], ","):
                nm = _declarator_name(d)
                if nm:
                    names.append(nm)
        else:
            m = fnptr(s1)
            if m:
                names.append(m.group(1))
            else:
                nm = _declarator_name(s1)
                if nm:
                    names.append(nm)
        it.names = names
    elif first in ("struct", "union", "enum") and re.match(r"(?:struct|union|enum)\s+(?:[A-Za-z_]\w*\s*)?\{", s1):
        it.kind = "type"
        names = []
        tag = re.match(r"(?:struct|union|enum)\s+([A-Za-z_]\w*)", s1)
        if tag:
            names.append(tag.group(1))
        if first == "enum":
            names += _enum_consts(s1)
        close = s1.rfind("}")
        for d in _top_split(s1[close + 1:], ","):
            nm = _declarator_name(d)
            if nm:
                names.append(nm)
                it.kind = "var"
        it.names = names
    else:
        eq = _top_split(s1, "=")
        before = eq[0]
        p = before.find("(")
        is_fp = bool(fnptr(before)) or (p >= 0 and _type_macro(before, p))
        if p >= 0 and not is_fp and len(IDENT.findall(before[:p])) >= 2:
            it.kind = "proto"
            it.names = [IDENT.findall(before[:p])[-1]]
        elif p >= 0 and not is_fp:
            it.kind = "macrocall"
            it.names = []
            idx = MACRO_DEFS.get(first)
            if idx is not None:
                args = _top_split(before[p + 1:before.rfind(")")], ",")
                if idx < len(args):
                    m = IDENT.search(args[idx])
                    if m:
                        it.names = [m.group(0)]
        else:
            it.kind = "externvar" if first == "extern" else "var"
            names = []
            for d in _top_split(s1, ","):
                nm = _declarator_name(d)
                if nm:
                    names.append(nm)
            # the first declarator carries the type; later ones are names only
            it.names = names
    for nm in it.names:
        it.refs.discard(nm)


STORAGE = {"static", "extern", "const", "volatile", "register", "inline", "__inline", "__forceinline"}


def _type_macro(before, p):
    """True when the '(' at p belongs to a type written as a macro call, as in
    'static STACK_OF(X509) *certs = NULL;': only storage words before the macro name, and a
    declarator after its closing parenthesis. Such a line declares data, not a function."""
    pre = [x for x in IDENT.findall(before[:p]) if x not in STORAGE]
    if len(pre) != 1:
        return False
    depth = 0
    for q in range(p, len(before)):
        if before[q] == "(":
            depth += 1
        elif before[q] == ")":
            depth -= 1
            if depth == 0:
                return re.fullmatch(r"\s*\**\s*[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)*", before[q + 1:]) is not None
    return False


def _enum_consts(s):
    a = s.find("{")
    b = s.rfind("}")
    out = []
    for part in _top_split(s[a + 1:b], ","):
        m = IDENT.search(part)
        if m:
            out.append(m.group(0))
    return out


# ---- include closure and header-visible names

def resolve_include(name, from_dir, src_root):
    for d in (from_dir, src_root, os.path.join(src_root, "Cedar"), os.path.join(src_root, "Mayaqua")):
        p = os.path.normpath(os.path.join(d, name))
        if os.path.isfile(p):
            return p
    return None


INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)


def include_closure(path, src_root, cache=None):
    seen = []
    stack = [path]
    visited = set()
    while stack:
        p = stack.pop()
        if p in visited:
            continue
        visited.add(p)
        if p != path:
            seen.append(p)
        txt = read_text(p)
        for m in INCLUDE_RE.finditer(mask_keep_includes(txt)):
            r = resolve_include(m.group(1), os.path.dirname(p), src_root)
            if r:
                stack.append(r)
    return seen


def mask_keep_includes(txt):
    # drop comments only, keep string contents (include names live in quotes)
    txt = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), txt, flags=re.S)
    return re.sub(r"//[^\n]*", "", txt)


_hdr_cache = {}


def header_names(path):
    """Every name a header declares or defines (prototypes, extern data, types, macros)."""
    if path in _hdr_cache:
        return _hdr_cache[path]
    names = set()
    try:
        cf = CFile(path)
        for it in cf.walk():
            names.update(it.names)
    except ParseError:
        # fall back to a token scan: anything that looks like a declaration name
        code = mask(read_text(path))
        names.update(re.findall(r"([A-Za-z_]\w*)\s*\(", code))
        names.update(re.findall(r"#\s*define\s+([A-Za-z_]\w*)", code))
        names.update(IDENT.findall(code))
    _hdr_cache[path] = names
    return names


def visible_names(path, src_root):
    out = set()
    for h in include_closure(path, src_root):
        if h.endswith((".h", ".hpp")):
            out |= header_names(h)
    return out


def newline_of(text):
    return "\r\n" if "\r\n" in text[:4000] else "\n"
