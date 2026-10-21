# Fixtures for move-only-check.py (spec #29, Testing Decisions).
#
# Builds a throwaway git repository with hand-made commits and checks that the checker passes a
# real pure move and fails each forbidden change: one changed character, two swapped functions,
# a function deleted without reappearing, half a function moved, an extra line in a new file, a
# header edit inside a split commit, plus the gaps the checker also closes (a block that leaves
# its #if, an include the source does not have, a destination that grows in the middle, a CR
# inside a line, header and linkage commits that edit code, and an unmarked commit that moves
# code). A CRLF source moved into an LF file passes: git normalizes line endings (text=auto).
# A split into a new internal header passes with its guard and the one #include it adds to
# the source; any other source line, another header's include, or the include inside an #if fails.
# A linkage commit that removes "static " from a function without a static prototype may declare
# it by its definition head; another head, or a declaration while "static " stays, fails.
#
# Usage: python -I move-only-check-test.py

import os
import subprocess
import sys
import tempfile

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'move-only-check.py')

PRE = '// A.c\n// Test module\n\n#include "A.h"\n#include <string.h>\n\n#ifndef NO_X\n#include <x.h>\n#endif\n'
F1 = 'int F1(int a)\n{\n\treturn a + 1;\n}\n'
F2 = '// F2 doubles\nint F2(int b)\n{\n\tif (b)\n\t{\n\n\t\treturn 2;\n\t}\n\treturn 0;\n}\n'
F2_CR = F2.replace('return 2;', 'return\r 2;')
F2_HEAD ='// F2 doubles\nint F2(int b)\n{\n\tif (b)\n\t{\n\n\t\treturn 2;\n\t}\n'
F2_TAIL = '\treturn 0;\n}\n'
F3 = 'int F3(void)\n{\n\treturn 3;\n}\n'
F4 = '#ifdef FEATURE\nint F4(void)\n{\n\treturn 4;\n}\n#endif\n'
F4_IN = 'int F4(void)\n{\n\treturn 4;\n}\n'
MAC = '#define TWICE(x) \\\n\t((x) + \\\n\t (x))\n'
F5 = 'int F5(void)\n{\n\treturn 5;\n}\n'
CPRE = '// C.c\n// Split out of A.c\n\n#include "A.h"\n'
A_H = '// A.h\n\n#ifndef\tA_H\n#define\tA_H\n\nint F1(int a);\nint F2(int b);\nint F3(void);\n#define LIMIT 10\n\n#endif\n'
B_C = '// B.c\n\n#include "A.h"\n\nint G1(void)\n{\n\treturn 1;\n}\n'
B_H = '// B.h\n\n#ifndef\tB_H\n#define\tB_H\n\nint G1(void);\n\n#endif\n'


PRE_I = PRE.replace('#include "A.h"\n', '#include "A.h"\n#include "AInternal.h"\n')
A_INT = '// AInternal.h\n// Shared inside module A\n\n#ifndef\tA_INTERNAL_H\n#define\tA_INTERNAL_H\n\n' + MAC + '\n#endif\n'


S_INT = '// SInternal.h\n\n#ifndef\tS_INTERNAL_H\n#define\tS_INTERNAL_H\n\n#endif\n'
S_C = ('// S.c\n\n#include "A.h"\n#include "SInternal.h"\n\nstatic int F3(void);\n\n'
       'static int H(void)\n{\n\treturn 7;\n}\n\n'
       'int G(void)\n{\n\treturn F3() + H();\n}\n\nstatic int F3(void)\n{\n\treturn 3;\n}\n')


def a_c(*blocks):
    return PRE + ''.join('\n' + b for b in blocks)


def c_c(*blocks, pre=CPRE):
    return pre + ''.join('\n' + b for b in blocks)


def crlf(s):
    return s.replace('\n', '\r\n')


BASE = {
    'A.c': a_c(F1, F2, F3, F4, MAC, F5),
    'A.h': A_H,
    'B.c': B_C,
    'B.h': B_H,
    'W.c': crlf(a_c(F1, F2, F3, F4, MAC, F5)),
    'R.c': a_c(F1, F2_CR),
    'S.c': S_C,
    'SInternal.h': S_INT,
}

# (name, subject, files changed against BASE, expect pass, check a --range instead of the commit)
CASES = [
    ('pure move to a new file', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2)}, True, False),
    ('two blocks in order', 'split: F2 F3', {'A.c': a_c(F1, F4, MAC, F5), 'C.c': c_c(F2, F3)}, True, False),
    ('append to an existing file', 'split: F3', {'A.c': a_c(F1, F2, F4, MAC, F5), 'B.c': B_C + '\n' + F3}, True, False),
    ('extra separator lines', 'split: F2 F3', {'A.c': a_c(F1, F4, MAC, F5), 'C.c': CPRE + '\n\n' + F2 + '\n\n\n' + F3}, True, False),
    ('whole #if group', 'split: F4', {'A.c': a_c(F1, F2, F3, MAC, F5), 'C.c': c_c(F4)}, True, False),
    ('continued macro', 'split: TWICE', {'A.c': a_c(F1, F2, F3, F4, F5), 'C.c': c_c(MAC)}, True, False),
    ('conditional include from the preamble', 'split: F2',
     {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': '// C.c\n\n#include "A.h"\n\n#ifndef NO_X\n#include <x.h>\n#endif\n\n' + F2}, True, False),
    ('CRLF kept', 'split: F2', {'W.c': crlf(a_c(F1, F3, F4, MAC, F5)), 'C.c': crlf(c_c(F2))}, True, False),
    ('one changed character', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2.replace('return 2', 'return 3'))}, False, False),
    ('two functions swapped', 'split: F2 F3', {'A.c': a_c(F1, F4, MAC, F5), 'C.c': c_c(F3, F2)}, False, False),
    ('deleted without reappearing', 'split: F2', {'A.c': a_c(F1, F4, MAC, F5), 'C.c': c_c(F2)}, False, False),
    ('deleted, no destination', 'split: F3', {'A.c': a_c(F1, F2, F4, MAC, F5)}, False, False),
    ('half a function moved', 'split: F2 tail', {'A.c': PRE + '\n' + F1 + '\n' + F2_HEAD + '\n' + F3 + '\n' + F4 + '\n' + MAC + '\n' + F5,
                                                 'C.c': c_c(F2_TAIL)}, False, False),
    ('extra line in a new file', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2) + '\nint extra;\n'}, False, False),
    ('extra line in the preamble', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2, pre=CPRE + 'static int x;\n')}, False, False),
    ('header edit inside a split', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2), 'A.h': A_H.replace('int F2(int b);\n', '')}, False, False),
    ('include the source lacks', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2, pre='// C.c\n\n#include "B.h"\n')}, False, False),
    ('block leaves its #if', 'split: F4', {'A.c': a_c(F1, F2, F3, '#ifdef FEATURE\n#endif\n', MAC, F5), 'C.c': c_c(F4_IN)}, False, False),
    ('destination grows in the middle', 'split: F3', {'A.c': a_c(F1, F2, F4, MAC, F5), 'B.c': '// B.c\n\n#include "A.h"\n\n' + F3 + '\nint G1(void)\n{\n\treturn 1;\n}\n'}, False, False),
    ('source gains a line', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5) + 'int z;\n', 'C.c': c_c(F2)}, False, False),
    ('CRLF source into an LF file', 'split: F2', {'W.c': crlf(a_c(F1, F3, F4, MAC, F5)), 'C.c': c_c(F2)}, True, False),
    ('CR inside a moved line kept', 'split: F2', {'R.c': a_c(F1), 'C.c': c_c(F2_CR)}, True, False),
    ('CR inside a moved line dropped', 'split: F2', {'R.c': a_c(F1), 'C.c': c_c(F2)}, False, False),
    ('split to a new internal header', 'split: TWICE to AInternal.h',
     {'A.c': a_c(F1, F2, F3, F4, F5).replace(PRE, PRE_I), 'AInternal.h': A_INT}, True, False),
    ('new header plus another source line', 'split: TWICE to AInternal.h',
     {'A.c': a_c(F1, F2, F3, F4, F5).replace(PRE, PRE_I) + 'int z;\n', 'AInternal.h': A_INT}, False, False),
    ('include of a different header', 'split: TWICE to AInternal.h',
     {'A.c': a_c(F1, F2, F3, F4, F5).replace(PRE, PRE_I.replace('AInternal.h', 'BInternal.h')), 'AInternal.h': A_INT}, False, False),
    ('include of the new header inside an #if', 'split: TWICE to AInternal.h',
     {'A.c': a_c(F1, F2, F3, F4, F5).replace(PRE, PRE.replace('#include <x.h>\n', '#include <x.h>\n#include "AInternal.h"\n')),
      'AInternal.h': A_INT}, False, False),
    ('include added for an existing destination', 'split: F3',
     {'A.c': a_c(F1, F2, F4, MAC, F5).replace(PRE, PRE.replace('#include "A.h"\n', '#include "A.h"\n#include "B.h"\n')),
      'B.c': B_C + '\n' + F3}, False, False),
    ('header: include in a .c file', 'header: B.h in A.c', {'A.c': BASE['A.c'].replace('#include <string.h>\n', '#include <string.h>\n#include "B.h"\n')}, True, False),
    ('header: declaration moved', 'header: F3 to B.h', {'A.h': A_H.replace('int F3(void);\n', ''), 'B.h': B_H.replace('int G1(void);\n', 'int G1(void);\nint F3(void);\n')}, True, False),
    ('header: new header with a guard', 'header: C.h', {'A.h': A_H.replace('int F2(int b);\n', ''), 'C.h': '// C.h\n\n#ifndef\tC_H\n#define\tC_H\n\nint F2(int b);\n\n#endif\n'}, True, False),
    ('header: statement edited', 'header: F1', {'A.c': BASE['A.c'].replace('return a + 1', 'return a + 2')}, False, False),
    ('header: constant changed', 'header: LIMIT', {'A.h': A_H.replace('LIMIT 10', 'LIMIT 11')}, False, False),
    ('header: guard with a value', 'header: C.h', {'A.h': A_H.replace('int F2(int b);\n', ''), 'C.h': '// C.h\n\n#ifndef\tC_H\n#define\tC_H 1\n\nint F2(int b);\n\n#endif\n'}, False, False),
    ('linkage: static and prototype', 'linkage: F3', {'A.c': BASE['A.c'].replace('int F3(void)\n{', 'static int F3(void)\n{'), 'A.h': A_H.replace('int F3(void);\n', '')}, True, False),
    ('linkage: with an edit', 'linkage: F3', {'A.c': BASE['A.c'].replace('int F3(void)\n{\n\treturn 3;', 'static int F3(void)\n{\n\treturn 4;')}, False, False),
    ('linkage: static removed, prototype to a header', 'linkage: F3 visible in module S',
     {'S.c': S_C.replace('static int F3(void);\n\n', '').replace('static int F3(void)\n{', 'int F3(void)\n{'),
      'SInternal.h': S_INT.replace('\n\n#endif', '\n\nint F3(void);\n\n#endif')}, True, False),
    ('linkage: prototype changed on the way', 'linkage: F3 visible in module S',
     {'S.c': S_C.replace('static int F3(void);\n\n', '').replace('static int F3(void)\n{', 'int F3(void)\n{'),
      'SInternal.h': S_INT.replace('\n\n#endif', '\n\nint F3(int x);\n\n#endif')}, False, False),
    ('linkage: static removed with an edit', 'linkage: F3 visible in module S',
     {'S.c': S_C.replace('static int F3(void);\n\n', '').replace('static int F3(void)\n{\n\treturn 3;', 'int F3(void)\n{\n\treturn 4;'),
      'SInternal.h': S_INT.replace('\n\n#endif', '\n\nint F3(void);\n\n#endif')}, False, False),
    ('linkage: prototype deleted, declared nowhere', 'linkage: F3 visible in module S',
     {'S.c': S_C.replace('static int F3(void);\n\n', '').replace('static int F3(void)\n{', 'int F3(void)\n{')}, False, False),
    ('linkage: other line deleted', 'linkage: F3 visible in module S',
     {'S.c': S_C.replace('#include "A.h"\n', '').replace('static int F3(void)\n{', 'int F3(void)\n{')}, False, False),
    ('linkage: static removed, declared by its head', 'linkage: H visible in module S',
     {'S.c': S_C.replace('static int H(void)\n{', 'int H(void)\n{'),
      'SInternal.h': S_INT.replace('\n\n#endif', '\n\nint H(void);\n\n#endif')}, True, False),
    ('linkage: declared with another head', 'linkage: H visible in module S',
     {'S.c': S_C.replace('static int H(void)\n{', 'int H(void)\n{'),
      'SInternal.h': S_INT.replace('\n\n#endif', '\n\nint H(int x);\n\n#endif')}, False, False),
    ('linkage: declared, static kept', 'linkage: H visible in module S',
     {'SInternal.h': S_INT.replace('\n\n#endif', '\n\nint H(void);\n\n#endif')}, False, False),
    ('unmarked commit that moves code', 'Refactor F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'B.c': B_C.replace('return 1', 'return 0') + '\n' + F2}, False, True),
    ('unmarked commit that only edits', 'Fix F1', {'A.c': BASE['A.c'].replace('return a + 1', 'return a + 2')}, True, True),
    ('unmarked extract of a function part', 'Extract F2 core',
     {'A.c': BASE['A.c'].replace('\tif (b)\n\t{\n\n\t\treturn 2;\n\t}\n', '\tif (F2Core(b))\n\t{\n\t\treturn 2;\n\t}\n'),
      'B.c': B_C + '\nint F2Core(int b)\n{\n\tif (b)\n\t{\n\n\t\treturn 2;\n\t}\n\treturn 0;\n}\n'}, True, True),
    ('marked failure inside a range', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F3)}, False, True),
]


def git(repo, *args):
    return subprocess.run(['git'] + list(args), cwd=repo, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout.decode().strip()


def write(repo, files):
    for name, text in files.items():
        path = os.path.join(repo, name)
        if text is None:
            os.remove(path)
        else:
            with open(path, 'wb') as f:
                f.write(text.encode('latin-1'))


def commit(repo, files, subject):
    write(repo, files)
    git(repo, 'add', '-A')
    git(repo, 'commit', '-q', '-m', subject)
    return git(repo, 'rev-parse', 'HEAD')


def checker(repo, *args):
    p = subprocess.run([sys.executable, '-I', CHECKER, '--repo', repo] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode('utf-8', 'replace')


def main():
    bad = 0
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as repo:
        git(repo, 'init', '-q')
        for k, v in (('user.name', 'fixture'), ('user.email', 'fixture@example.invalid'),
                     ('core.autocrlf', 'false'), ('commit.gpgsign', 'false')):
            git(repo, 'config', k, v)
        base = commit(repo, BASE, 'base')

        def case(name, subject, files, expect, as_range):
            git(repo, 'checkout', '-q', '--detach', base)
            sha = commit(repo, files, subject)
            code, out = checker(repo, '--range', base + '..' + sha) if as_range else checker(repo, sha)
            return sha, code, out, (code == 0) == expect

        for name, subject, files, expect, as_range in CASES:
            sha, code, out, ok = case(name, subject, files, expect, as_range)
            print('%s %-40s expected %s, got %s' % ('ok  ' if ok else 'BAD ', name, 'pass' if expect else 'fail',
                                                     'pass' if code == 0 else 'fail'))
            if not ok:
                bad += 1
                print('     ' + out.replace('\n', '\n     '))
            elif code != 0:
                print('     ' + out.strip().splitlines()[1].strip())

        # A waived commit is reported and skipped, so a mistake that landed can be fixed forward.
        git(repo, 'checkout', '-q', '--detach', base)
        moved = commit(repo, {'A.c': a_c(F1, F3, F4, MAC, F5), 'B.c': B_C + '\n' + F2}, 'Refactor F2')
        os.makedirs(os.path.join(repo, '.github'), exist_ok=True)
        head = commit(repo, {'.github/move-only-waivers.txt': '%s fixture: moved before the rule\n' % moved}, 'Waive it')
        code, out = checker(repo, '--range', base + '..' + head)
        ok = code == 0 and 'WAIVED' in out
        print('%s %-40s expected pass, got %s' % ('ok  ' if ok else 'BAD ', 'waived commit', 'pass' if code == 0 else 'fail'))
        if not ok:
            bad += 1
            print('     ' + out.replace('\n', '\n     '))

        # Submodules have no lines: a split that touches one fails, an unmarked commit is skipped.
        for name, subject, files, expect in (
                ('submodule inside a split', 'split: F2', {'A.c': a_c(F1, F3, F4, MAC, F5), 'C.c': c_c(F2)}, False),
                ('unmarked submodule bump', 'Bump sub', {}, True)):
            git(repo, 'checkout', '-q', '--detach', base)
            write(repo, files)
            git(repo, 'add', '-A')
            git(repo, 'update-index', '--add', '--cacheinfo', '160000,%s,sub' % base)
            git(repo, 'commit', '-q', '-m', subject)
            sha = git(repo, 'rev-parse', 'HEAD')
            code, out = checker(repo, sha) if subject.startswith('split') else checker(repo, '--range', base + '..' + sha)
            ok = (code == 0) == expect and 'Traceback' not in out
            print('%s %-40s expected %s, got %s' % ('ok  ' if ok else 'BAD ', name, 'pass' if expect else 'fail',
                                                     'pass' if code == 0 else 'fail'))
            if not ok:
                bad += 1
                print('     ' + out.replace('\n', '\n     '))
            git(repo, 'reset', '-q', '--hard')

    total = len(CASES) + 3
    print('move-only checker fixtures: %d of %d as expected' % (total - bad, total))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
