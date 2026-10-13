"""Move-only checker for the god-file splits (issue #29).

Proves that a commit (or the working tree) only moves top-level definitions between files:

  * every top-level item of a changed C file before the change (function, prototype, file-scope
    data, type, macro, #if region, each with the comment written directly above it) appears
    byte for byte exactly once after it, in some file;
  * the items that move from one file to another keep their relative order, and so do the items
    that stay;
  * nothing is added except: #include lines; in a new file, its comment header and a copy of the
    include block (prologue) of the file it was split from; in a new header, its include guard;
    and CMakeLists.txt lines that name new sources;
  * comments that belong to no item stay as they are in every file that existed before;
  * no other file changes.

Usage (from the repository root):
    python tools/split/check_moves.py                 # HEAD against HEAD^
    python tools/split/check_moves.py --base REV --head REV
    python tools/split/check_moves.py --base REV --worktree
Exit status 0 when every rule holds; otherwise the first broken rule is printed with file and line.
"""
import argparse
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import splitlib as S  # noqa: E402


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo] + list(args), capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def changed_files(repo, base, head):
    if head is None:
        out = git(repo, "diff", "--name-status", "--no-renames", base).decode()
        files = [ln.split("\t", 1) for ln in out.splitlines() if ln]
        for f in git(repo, "ls-files", "--others", "--exclude-standard").decode().splitlines():
            files.append(["A", f])
    else:
        out = git(repo, "diff", "--name-status", "--no-renames", base, head).decode()
        files = [ln.split("\t", 1) for ln in out.splitlines() if ln]
    return [(st, f.replace("\\", "/")) for st, f in files]


def read_rev(repo, rev, path):
    if rev is None:
        p = os.path.join(repo, path)
        return S.read_text(p) if os.path.isfile(p) else None
    r = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout.decode("latin-1")


class Fail(Exception):
    pass


def gaps(cf):
    """Comment lines that belong to no item, in order, without blank lines."""
    covered = set()
    for it in cf.items:
        covered.update(range(it.l0, it.l1 + 1))
    if cf.guard:
        covered.update(range(cf.guard.l0, cf.guard.cl + 1))
        covered.add(cf.guard.l1)
    out = []
    for i, t in enumerate(cf.lines):
        if i not in covered and t.strip():
            out.append((i, t.rstrip("\r")))
    return out


def main():
    ap = argparse.ArgumentParser(description="move-only checker for the god-file splits (#29)")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base", default=None)
    ap.add_argument("--head", default=None)
    ap.add_argument("--worktree", action="store_true")
    ap.add_argument("--macro-defines", default="DECLARE_SC=2,DECLARE_SC_EX=2,DECLARE_RPC=2,DECLARE_RPC_EX=2")
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    for kv in a.macro_defines.split(","):
        if kv:
            k, v = kv.split("=")
            S.MACRO_DEFS[k] = int(v)
    head = None if a.worktree else (a.head or "HEAD")
    base = a.base or ("HEAD" if a.worktree else head + "^")
    try:
        check(repo, base, head)
    except Fail as e:
        print(f"check_moves: FAIL: {e}")
        sys.exit(1)


def check(repo, base, head):
    files = changed_files(repo, base, head)
    before, after = {}, {}
    for st, f in files:
        if f.endswith((".c", ".h")):
            b = read_rev(repo, base, f)
            h = read_rev(repo, head, f)
            try:
                if b is not None:
                    before[f] = S.CFile(path=f, text=b)
                if h is not None:
                    after[f] = S.CFile(path=f, text=h)
            except S.ParseError as e:
                raise Fail(f"{e} (only whole top-level blocks may move)")
        elif os.path.basename(f) == "CMakeLists.txt":
            b = read_rev(repo, base, f) or ""
            h = read_rev(repo, head, f) or ""
            bl, hl = b.splitlines(), h.splitlines()
            import difflib
            for d in difflib.ndiff(bl, hl):
                if d.startswith("- "):
                    raise Fail(f"{f}: line removed: {d[2:].strip()}")
                if d.startswith("+ ") and not re.fullmatch(r"\s*[\w./-]+\.c\s*", d[2:]):
                    raise Fail(f"{f}: added line is not a source name: {d[2:].strip()}")
        else:
            raise Fail(f"{f}: changed, but a split commit only touches C sources, headers and CMakeLists.txt")

    # prologue items of the files that existed before (a new file may copy them)
    prologue_texts = set()
    for f, cf in before.items():
        for it in cf.items[:cf.prologue_end()]:
            prologue_texts.add(it.text)
        if cf.guard:
            prologue_texts.add(cf.ltext(cf.guard.l0, cf.guard.cl).strip())
            prologue_texts.add(cf.ltext(cf.guard.cl, cf.guard.cl).strip())

    # base occurrences per text (the newline that ends the last line does not count)
    def key(it):
        return it.text.rstrip("\r\n")

    occ = {}
    for f in sorted(before):
        for k, it in enumerate(before[f].items):
            occ.setdefault(key(it), []).append([f, k, False])

    moved_pairs = {}
    added = {"include": 0, "prologue": 0, "guard": 0}
    moved = 0
    matched = {}
    # pass 1: blocks that stay in their file
    for f in sorted(after):
        for k, it in enumerate(after[f].items):
            for c in occ.get(key(it), ()):
                if not c[2] and c[0] == f:
                    c[2] = True
                    matched[(f, k)] = c
                    break
    # pass 2: blocks that moved, and the additions a split may make
    for f in sorted(after):
        cf = after[f]
        new_file = f not in before
        pe = cf.prologue_end()
        guard_name = None
        if cf.guard and f.endswith(".h"):
            m = re.match(r"\s*#\s*ifndef\s+(\w+)", cf.lines[cf.guard.cl])
            guard_name = m.group(1) if m else None
        if new_file and cf.guard:
            g = cf.ltext(cf.guard.l0, cf.guard.cl).strip()
            if not f.endswith(".h") and g not in prologue_texts:
                raise Fail(f"{f}:{cf.guard.cl + 1}: new file wrapped in a conditional that its source file does not have")
        for k, it in enumerate(cf.items):
            if (f, k) in matched:
                c = matched[(f, k)]
                moved_pairs.setdefault((c[0], f), []).append((c[1], k, it))
                continue
            if new_file and k < pe and (it.kind == "include" or it.text in prologue_texts):
                added["prologue"] += 1
                continue
            if new_file and guard_name and it.kind == "macro" and it.names == [guard_name] and k == 0:
                added["guard"] += 1
                continue
            pick = None
            for c in occ.get(key(it), ()):
                if not c[2]:
                    pick = c
                    break
            if pick is not None:
                pick[2] = True
                moved_pairs.setdefault((pick[0], f), []).append((pick[1], k, it))
                moved += 1
                continue
            if it.kind == "include":
                added["include"] += 1
                continue
            raise Fail(f"{f}:{it.cl + 1}: added or changed {it.kind} {','.join(it.all_names())[:80]!s} "
                       f"that is not a byte-for-byte copy of a block removed elsewhere")
    for t, cands in occ.items():
        for f, k, used in cands:
            if not used:
                it = before[f].items[k]
                if it.kind == "include" and f in after:
                    raise Fail(f"{f}:{it.cl + 1}: #include removed")
                raise Fail(f"{f}:{it.cl + 1}: {it.kind} {','.join(it.all_names())[:80]} removed and not found in any changed file")

    for (src, dst), seq in moved_pairs.items():
        seq.sort(key=lambda x: x[1])
        last = -1
        for bi, hk, it in seq:
            if bi < last:
                raise Fail(f"{dst}:{it.cl + 1}: {','.join(it.all_names())[:60]} from {src} is out of its original order")
            last = bi

    for f in before:
        if f in after:
            gb = [t for _, t in gaps(before[f])]
            ga = [t for _, t in gaps(after[f])]
            if gb != ga:
                for x, y in zip(gb + [""] * len(ga), ga + [""] * len(gb)):
                    if x != y:
                        raise Fail(f"{f}: comment outside any block changed: {x[:60]!r} -> {y[:60]!r}")
            if bool(before[f].guard) != bool(after[f].guard):
                raise Fail(f"{f}: file-wide conditional added or removed")
    for f in after:
        if f not in before:
            cf = after[f]
            first_item = cf.items[0].l0 if cf.items else len(cf.lines)
            if cf.guard:
                first_item = min(first_item, cf.guard.l0)
            for i, t in gaps(cf):
                if i > first_item:
                    raise Fail(f"{f}:{i + 1}: comment outside any block in a new file: {t[:60]!r}")
                if not t.lstrip().startswith("//"):
                    raise Fail(f"{f}:{i + 1}: header text that is not a comment: {t[:60]!r}")

    lines_b = sum(len(cf.lines) for cf in before.values())
    lines_a = sum(len(cf.lines) for cf in after.values())
    print(f"check_moves: OK: {moved} blocks moved across {len([p for p in moved_pairs if p[0] != p[1]])} file pairs; "
          f"{len([f for f in after if f not in before])} new files; added {added['include']} include lines, "
          f"{added['prologue']} copied prologue blocks, {added['guard']} include guards; "
          f"lines in changed C files {lines_b} -> {lines_a}")


if __name__ == "__main__":
    main()
