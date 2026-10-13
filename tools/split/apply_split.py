"""Split the god files of Ranz VPN by responsibility, as tools/split/split-map.json says (issue #29).

Usage (from the repository root):
    python tools/split/apply_split.py [--map tools/split/split-map.json] [--module Server] [--dry-run]

What it does, for each module of the map:
  1. Parses the god file into top-level items (splitlib.py) and assigns each item a destination
     file from the map: explicit names first, then the first matching pattern.
  2. Keeps every file-local symbol with all of its users. A static function or variable, a
     function or variable that no included header declares, and a prototype written in the .c
     file can only be seen from the file that holds it, so the items that use one are joined into
     a group that moves as a whole. A group whose members the map sends to different files stays
     in the god file, with a warning: the build would fail otherwise.
  3. Places the file's own macros, types and extern declarations ("hoistables") next to their
     users: in the one file that uses them, or in the module-internal header when several do.
  4. Moves every item verbatim, with the comment written directly above it, in its original
     order. A new file starts with the god file's comment header and its include block (the
     same headers, so the moved code sees the same declarations).
  5. Moves the prototypes that only the module's own files use from the API header (the
     god file's same-named header) to the module-internal header, which every file of the
     module includes after its include block.
  6. Checks that the CMakeLists.txt of the directory picks up the new files (Cedar and Mayaqua
     glob *.c); adds them when a list names its sources one by one.
  7. Reports every item that the map does not place (it stays in the god file) and every group
     kept back by a conflict.

Running it again on its own output changes nothing. A name missing from the map stays where it
is, with a warning. The map is meant to be re-applied on the tree that #24 and #28 leave: run
the tool on that tree and check the result with tools/split/check_moves.py.
"""
import argparse
import json
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import splitlib as S  # noqa: E402

HOISTABLE = ("macro", "type", "externvar")


class UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def shadowed(name, code):
    """True when a function declares its own parameter or local variable called name."""
    pat = r"\b(?!(?:return|else|case|goto|sizeof|typedef|do)\b)[A-Za-z_]\w*(?:\s+|\s+\*+)" + re.escape(name) + r"\s*[=;,\[\)]"
    return re.search(pat, code) is not None


class Module:
    def __init__(self, repo, cfg, log, explain=False):
        self.explain = explain
        self.repo = repo
        self.cfg = cfg
        self.log = log
        self.src_path = os.path.join(repo, cfg["source"])
        self.dir = os.path.dirname(self.src_path)
        self.src_root = os.path.join(repo, "src")
        self.base = os.path.splitext(os.path.basename(self.src_path))[0]
        self.api_path = os.path.join(repo, cfg.get("api_header", cfg["source"][:-2] + ".h"))
        self.int_name = cfg.get("internal_header", self.base + "Internal.h")
        self.int_path = os.path.join(self.dir, self.int_name)
        self.dests = [d["file"] for d in cfg["files"]]
        self.desc = {d["file"]: d.get("description", "") for d in cfg["files"]}

    # ---- map lookup
    def build_matchers(self):
        self.exact = {}
        self.patterns = []
        groups = [(d["file"], d) for d in self.cfg["files"]]
        groups.append((os.path.basename(self.src_path), self.cfg.get("remainder", {})))
        for dest, g in groups:
            for n in g.get("names", []):
                if n in self.exact and self.exact[n] != dest:
                    self.log.warn(f"{self.base}: {n} is mapped to both {self.exact[n]} and {dest}; using {self.exact[n]}")
                    continue
                self.exact[n] = dest
            for p in g.get("patterns", []):
                self.patterns.append((re.compile(p), dest))

    def wanted_for_name(self, n, patterns=True):
        if n in self.exact:
            return self.exact[n]
        if patterns:
            for rx, dest in self.patterns:
                if rx.search(n):
                    return dest
        return None

    def wanted(self, it):
        """The file the map asks for. Exact names apply to every kind of item; patterns only to
        functions, macro-generated functions and #if regions, so that file-scope data, macros and
        types follow the code that uses them unless the map names them."""
        names = it.all_names() if it.kind == "cond" else it.names
        ds = {self.wanted_for_name(n, False) for n in names} - {None}
        if not ds and it.kind in ("func", "macrocall", "cond"):
            ds = {self.wanted_for_name(n) for n in names} - {None}
        if len(ds) > 1:
            self.log.warn(f"{self.base}: the #if region at line {it.l0 + 1} holds names mapped to {sorted(ds)}; it stays whole in {self.base}.c")
            return os.path.basename(self.src_path)
        return ds.pop() if ds else None

    # ---- analysis
    def analyse(self):
        cf = S.CFile(self.src_path)
        self.cf = cf
        src_name = os.path.basename(self.src_path)
        pe = cf.prologue_end()
        items = cf.items[pe:]
        self.items = items
        visible = S.visible_names(self.src_path, self.src_root)

        defs = {}  # name -> item index (definition, or prototype when nothing defines it)
        func_defined = set()
        for i, it in enumerate(items):
            if it.kind in ("func", "var", "macrocall"):
                for n in it.names:
                    defs[n] = i
                    if it.kind == "func":
                        func_defined.add(n)
            elif it.kind == "cond":
                for n in it.all_names():
                    defs.setdefault(n, i)
        for i, it in enumerate(items):
            if it.kind in HOISTABLE or it.kind == "proto":
                for n in it.names:
                    defs.setdefault(n, i)

        def is_hoistable(i):
            it = items[i]
            if it.kind in HOISTABLE:
                return True
            if it.kind == "proto":
                return not any(n in func_defined for n in it.names)
            return False

        # local symbols: only the file that holds them can see them
        local = {}
        for n, i in defs.items():
            it = items[i]
            if is_hoistable(i):
                continue
            if it.kind == "cond":
                local[n] = i  # names inside a kept-whole #if region: treat as local to be safe
                if n in visible:
                    local.pop(n)
                continue
            if it.static or n not in visible:
                local[n] = i

        # hoistable names and their item
        hoist_of = {}
        for i, it in enumerate(items):
            if is_hoistable(i):
                for n in it.names:
                    hoist_of.setdefault(n, i)

        # effective references: through the file's own macros
        memo = {}

        def eff(i, stack=()):
            if i in memo:
                return memo[i]
            r = set(items[i].refs)
            for n in list(items[i].refs):
                h = hoist_of.get(n)
                if h is not None and h != i and h not in stack and items[h].kind == "macro":
                    r |= eff(h, stack + (i,))
            memo[i] = r
            return r

        # a hoistable used before its own definition cannot go to a header: pin it to its users
        pinned = set()
        for n, h in hoist_of.items():
            for i in range(h):
                if n in items[i].refs:
                    pinned.add(h)
                    break

        uf = UF()
        why = {}
        for i, it in enumerate(items):
            uf.find(i)
            refs = eff(i)
            for n in refs:
                d = local.get(n)
                if d is not None and d != i:
                    if it.kind == "func" and items[d].kind == "var" and shadowed(n, it.code):
                        continue
                    uf.union(i, d)
                    why.setdefault((min(i, d), max(i, d)), n)
                h = hoist_of.get(n)
                if h is not None and h in pinned and h != i:
                    uf.union(i, h)
            if it.kind == "proto" and not is_hoistable(i):
                for n in it.names:
                    if n in defs and defs[n] != i:
                        uf.union(i, defs[n])
        comps = {}
        for i in range(len(items)):
            comps.setdefault(uf.find(i), []).append(i)

        dest = [src_name] * len(items)
        want = [self.wanted(it) for it in items]
        self.conflicts = []
        for root, members in comps.items():
            free = [m for m in members if not (is_hoistable(m) and m not in pinned)]
            ws = {want[m] for m in free} - {None}
            if not ws:
                d = src_name
            elif len(ws) == 1:
                d = ws.pop()
            else:
                d = src_name
                self.conflicts.append((members, ws))
            for m in free:
                dest[m] = d

        # hoistables: next to their users, or in the internal header
        INTERNAL = "<internal>"
        hoist = [i for i in range(len(items)) if is_hoistable(i) and i not in pinned]
        users = {h: set() for h in hoist}
        for i in range(len(items)):
            r = items[i].refs
            for n in r:
                h = hoist_of.get(n)
                if h is not None and h in users and h != i:
                    users[h].add(i)
        hdest = {}
        changed = True
        while changed:
            changed = False
            for h in hoist:
                ds = set()
                for u in users[h]:
                    if u in users:  # another hoistable
                        if u in hdest:
                            ds.add(hdest[u])
                    else:
                        ds.add(dest[u])
                if not ds:
                    nd = src_name
                elif len(ds) == 1:
                    nd = ds.pop()
                else:
                    nd = INTERNAL
                if hdest.get(h) != nd:
                    hdest[h] = nd
                    changed = True
        for h in hoist:
            dest[h] = hdest[h]
        self.dest = dest
        self.want = want
        self.INTERNAL = INTERNAL
        self.why = why
        self.uf = uf
        self.local = local

    # ---- reporting
    def report(self):
        items = self.items
        src_name = os.path.basename(self.src_path)
        for members, ws in self.conflicts:
            names = []
            for m in members:
                nm = ",".join(items[m].all_names() if items[m].kind == "cond" else items[m].names) or items[m].kind
                names.append(f"{nm}->{self.want[m] or '-'}")
            links = sorted({v for (a, b), v in self.why.items() if a in members or b in members})
            self.log.warn(f"{self.base}: kept in {src_name}, file-local symbols ({', '.join(links[:12])}) tie together: " + " ".join(names[:60]))
            if self.explain:
                mset = set(members)
                for n, d in sorted(self.local.items()):
                    if d not in mset:
                        continue
                    by = {}
                    for m in members:
                        if m != d and n in self.items[m].refs:
                            nm = ",".join(items[m].names) or items[m].kind
                            by.setdefault(self.want[m] or "-", []).append(nm)
                    if len(by) > 1 or (by and (self.want[d] or "-") not in by):
                        self.log.info(f"    {n} [{self.want[d] or '-'}]: " + "; ".join(f"{k}: {' '.join(v)}" for k, v in sorted(by.items())))
        unplaced = []
        for i, it in enumerate(items):
            exported = it.kind == "var" and not it.static and not any(n in self.local for n in it.names)
            if self.want[i] is None and self.dest[i] == src_name and (it.kind in ("func", "macrocall", "cond") or exported):
                # an item that only follows its users is placed; an unused one is not
                unplaced.append(",".join(it.all_names() if it.kind == "cond" else it.names) or f"line {it.l0 + 1}")
        if unplaced:
            self.log.warn(f"{self.base}: {len(unplaced)} definitions not placed by the map stay in {src_name}: " + " ".join(unplaced))

    # ---- emission
    def plan_files(self):
        items = self.items
        cf = self.cf
        src_name = os.path.basename(self.src_path)
        moves = {}
        for i, d in enumerate(self.dest):
            if d != src_name:
                moves.setdefault(d, []).append(i)
        return moves

    def api_prune(self, module_files, index):
        """Prototype items of the API header that no file outside the module names."""
        if not self.cfg.get("prune_api_header", True) or not os.path.isfile(self.api_path):
            return None, []
        hf = S.CFile(self.api_path)
        module_set = {os.path.normcase(os.path.abspath(p)) for p in module_files}
        api_norm = os.path.normcase(os.path.abspath(self.api_path))
        defined = set()
        for p in module_files:
            if p.endswith(".c") and os.path.isfile(p):
                for it in S.CFile(p).walk():
                    if it.kind in ("func", "macrocall"):
                        defined.update(it.names)
        for it in self.items:
            if it.kind in ("func", "macrocall"):
                defined.update(it.names)
        pe = hf.prologue_end()
        out = []
        api_ids = {}
        for k, it in enumerate(hf.items[pe:]):
            for n in it.refs | set(it.names):
                api_ids.setdefault(n, set()).add(k)
        for k, it in enumerate(hf.items[pe:]):
            if it.kind != "proto" or not it.names:
                continue
            n = it.names[0]
            if n not in defined:
                continue
            outside = [f for f in index.get(n, ()) if f not in module_set and f != api_norm]
            if outside:
                continue
            if api_ids.get(n, set()) - {k}:
                continue
            out.append(it)
        return hf, out

    def apply(self, index, dry):
        items = self.items
        cf = self.cf
        src_name = os.path.basename(self.src_path)
        nl = S.newline_of(cf.text)
        moves = self.plan_files()
        internal_items = moves.pop(self.INTERNAL, [])
        dest_paths = [os.path.join(self.dir, d) for d in self.dests]
        module_files = [self.src_path] + dest_paths + [self.int_path]
        hf, pruned = self.api_prune(module_files, index)
        need_internal = bool(internal_items or pruned or os.path.isfile(self.int_path))
        inc_line = f'#include "{self.int_name}"'
        writes = {}

        prol_end = cf.prologue_lines()
        prologue = cf.ltext(0, prol_end - 1) if prol_end > 0 else ""
        epi_line = cf.epilogue_line()
        epilogue = cf.ltext(epi_line, len(cf.lines) - 1) if epi_line < len(cf.lines) else ""
        if cf.guard is None:
            epilogue = ""

        def with_include(text):
            if not need_internal or re.search(r'^\s*#\s*include\s+"' + re.escape(self.int_name) + '"', text, re.M):
                return text
            f = S.CFile(text=text, path="<mem>")
            pl = f.prologue_lines()
            a = f.starts[pl] if pl < len(f.starts) else len(text)
            return text[:a] + inc_line + nl + text[a:]

        # new or existing destination files
        for d, idxs in moves.items():
            path = os.path.join(self.dir, d)
            body = "".join(nl + items[i].text for i in idxs)
            if not body.endswith(nl):
                body += nl
            if os.path.isfile(path):
                old = S.read_text(path)
                df = S.CFile(text=old, path=path)
                el = df.epilogue_line() if df.guard else len(df.lines)
                a = df.starts[el] if el < len(df.starts) else len(old)
                if df.guard is None:
                    a = len(old)
                    if not old.endswith(nl):
                        old += nl
                        a = len(old)
                new = old[:a] + body + old[a:]
            else:
                new = self.header_comment(cf, d, nl) + prologue_body(cf, prol_end, nl) + body + (nl + epilogue if epilogue else "")
            writes[path] = with_include(new)

        # god file: remove moved items (and one blank line when it would leave two)
        drop = set()
        for d, idxs in list(moves.items()) + [(self.INTERNAL, internal_items)]:
            for i in idxs:
                it = items[i]
                for ln in range(it.l0, it.l1 + 1):
                    drop.add(ln)
        if drop:
            keep = drop_lines(cf.text.split("\n"), drop)
            new_src = "\n".join(keep)
            writes[self.src_path] = with_include(new_src)
        elif need_internal:
            ns = with_include(cf.text)
            if ns != cf.text:
                writes[self.src_path] = ns

        # internal header
        if internal_items or pruned:
            hnl = nl
            section = "".join(hnl + items[i].text for i in internal_items)
            if pruned:
                # the prototypes keep their grouping: one block, as in the API header
                section += hnl + "".join(it.text if it.text.endswith("\n") else it.text + hnl for it in pruned)
            if os.path.isfile(self.int_path):
                old = S.read_text(self.int_path)
                k = old.rfind("#endif")
                new = old[:k].rstrip("\r\n") + hnl + section + hnl + old[k:]
            else:
                guard = re.sub(r"[^A-Z0-9]", "_", self.base.upper()) + "_INTERNAL_H"
                head = self.header_comment(cf, self.int_name, hnl, internal=True)
                new = (head + f"#ifndef\t{guard}{hnl}#define\t{guard}{hnl}" + section + hnl + f"#endif\t// {guard}{hnl}")
            writes[self.int_path] = new
        if pruned:
            dropl = set()
            for it in pruned:
                dropl.update(range(it.l0, it.l1 + 1))
            keep = drop_lines(hf.text.split("\n"), dropl)
            writes[self.api_path] = "\n".join(keep)

        # every file of the module includes the internal header
        if need_internal:
            for p in dest_paths:
                if p not in writes and os.path.isfile(p):
                    t = S.read_text(p)
                    nt = with_include(t)
                    if nt != t:
                        writes[p] = nt

        self.moves = moves
        self.internal_items = internal_items
        self.pruned = pruned
        if not dry:
            for p, t in writes.items():
                S.write_text(p, t)
        return writes

    def header_comment(self, cf, name, nl, internal=False):
        """The god file's leading comment lines, with its file name and description replaced."""
        lines = []
        for i, ln in enumerate(cf.lines):
            if cf.clines[i].strip() != "":
                break
            lines.append(ln.rstrip("\r"))
        out = []
        i = 0
        src = os.path.basename(self.src_path)
        while i < len(lines):
            if re.match(r"//\s*" + re.escape(src) + r"\s*$", lines[i]):
                out.append("// " + name)
                desc = (f"Module-internal declarations of the {self.base} module: only its own files include this header"
                        if internal else self.desc.get(name, ""))
                if desc:
                    out.append("// " + desc)
                i += 1
                while i < len(lines) and lines[i].strip().startswith("//"):
                    i += 1
                continue
            out.append(lines[i])
            i += 1
        while out and out[-1].strip() == "":
            out.pop()
        return nl.join(out) + nl + nl


def prologue_body(cf, prol_end, nl):
    """The include block of the god file (everything after its leading comment, up to the end of the
    prologue)."""
    first = 0
    for i in range(len(cf.lines)):
        if cf.clines[i].strip() != "":
            first = i
            break
    if prol_end <= first:
        return ""
    return cf.ltext(first, prol_end - 1)


def drop_lines(lines, drop):
    """lines without the dropped ones; a blank line right after a dropped block goes too when the
    line kept before the block is blank, so no double blank lines are left behind."""
    keep = []
    for ln, t in enumerate(lines):
        if ln in drop:
            continue
        if t.strip() == "" and (ln - 1) in drop and keep and keep[-1].strip() == "":
            continue
        keep.append(t)
    return keep


def repo_index(repo):
    """identifier -> set of files (normalised paths) that name it, over the program sources."""
    index = {}
    roots = [os.path.join(repo, "src")]
    for r in roots:
        for dp, dn, fn in os.walk(r):
            if "3rdparty" in dp.replace("\\", "/").split("/"):
                continue
            for f in fn:
                if not f.endswith((".c", ".h", ".cpp")):
                    continue
                p = os.path.join(dp, f)
                code = S.mask(S.read_text(p))
                key = os.path.normcase(os.path.abspath(p))
                for n in set(S.IDENT.findall(code)):
                    index.setdefault(n, set()).add(key)
    return index


def update_cmake(repo, module, log, dry):
    cm = os.path.join(module.dir, "CMakeLists.txt")
    if not os.path.isfile(cm):
        return
    text = S.read_text(cm)
    if re.search(r'file\s*\(\s*GLOB\s+\w+\s+"\*\.c"', text):
        log.info(f"{os.path.relpath(cm, repo)}: globs *.c, new sources are picked up without an edit")
        return
    src = os.path.basename(module.src_path)
    m = re.search(r"^(\s*)" + re.escape(src) + r"\s*$", text, re.M)
    if not m:
        log.warn(f"{os.path.relpath(cm, repo)}: no glob and no line naming {src}; add the new sources by hand")
        return
    add = "".join(f"{m.group(1)}{d}\n" for d in module.dests if d not in text)
    if add and not dry:
        S.write_text(cm, text[:m.end() + 1] + add + text[m.end() + 1:])


class Log:
    def __init__(self):
        self.warnings = 0

    def warn(self, msg):
        self.warnings += 1
        print("warning: " + msg)

    def info(self, msg):
        print(msg)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--map", default=None)
    ap.add_argument("--module", action="append", help="only this module (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--explain", action="store_true", help="for each group kept back, show which file-local symbol ties which users")
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    mp = a.map or os.path.join(repo, "tools", "split", "split-map.json")
    with open(mp, encoding="utf-8") as f:
        cfg = json.load(f)
    S.MACRO_DEFS.update(cfg.get("macro_defines", {}))
    log = Log()
    index = repo_index(repo)
    total_before = total_after = 0
    for mc in cfg["modules"]:
        name = os.path.splitext(os.path.basename(mc["source"]))[0]
        if a.module and name not in a.module:
            continue
        m = Module(repo, mc, log, a.explain)
        m.build_matchers()
        m.analyse()
        m.report()
        writes = m.apply(index, a.dry_run)
        update_cmake(repo, m, log, a.dry_run)
        moved = sum(len(v) for v in m.moves.values())
        print(f"{name}: {moved} items moved to {len(m.moves)} files, {len(m.internal_items)} to {m.int_name}, "
              f"{len(m.pruned)} prototypes moved from {os.path.basename(m.api_path)} to {m.int_name}")
        for p in sorted(writes):
            print(f"  {os.path.relpath(p, repo)}: {writes[p].count(chr(10)) + 1} lines")
    print(f"{log.warnings} warning(s)")


if __name__ == "__main__":
    main()
