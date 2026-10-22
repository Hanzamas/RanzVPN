# Fixtures for the scripts of the ADR-0040 quality gates: fuzz-registry.py, coverage-floor.py,
# bench-gate.py and static-findings.py.
#
# Each gate runs on a throwaway tree or input made here and must pass what it should pass and fail
# what it should fail: a new parser without a fuzz target, a stale registry line, a fuzz target that
# CI would not run; a module below its floor or without one; a benchmark slower than its margin or
# missing; a new static analysis finding. So a gate that passes everything fails here first.
#
# Usage: python -I quality-gates-test.py

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
failures = []


def run(script, *args):
    p = subprocess.run([sys.executable, '-I', os.path.join(HERE, script)] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={k: v for k, v in os.environ.items()
                                                                              if k not in ('GITHUB_ACTIONS', 'GITHUB_STEP_SUMMARY', 'GITHUB_WORKSPACE')})
    return p.returncode, p.stdout.decode('utf-8', errors='replace')


def expect(name, result, code, *texts):
    got, out = result
    missing = [t for t in texts if t not in out]
    if got != code or missing:
        failures.append('%s: exit %d, want %d%s\n%s' % (name, got, code, ', missing %r' % missing if missing else '', out))
        print('FAIL', name)
    else:
        print('ok  ', name)


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


# A tree with one C parser and one Go parser, each with its fuzz target
CORE_C = ('// X.c\n#include "X.h"\n\nstatic bool XParseInner(const UCHAR *p) {\n\treturn p != NULL;\n}\n\n'
          'bool XDecode(const UCHAR *p, UINT size) {\n\treturn XParseInner(p);\n}\n\n'
          'void XFree(X *x,\n           UINT flags) {\n}\n')
FUZZ_C = '// fuzz_x.c\n// libFuzzer target: XDecode\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tXDecode(data, size);\n\treturn 0;\n}\n'
CMAKE = 'set(RANZ_FUZZ_TARGETS\n  fuzz_x\n)\n'
RUN_FUZZERS = "param(\n\t[string[]] $Targets = @('fuzz_x')\n)\n$MaxLen = @{ 'fuzz_x' = 4096 }\n"
GO_SRC = ('package wire\n\n// Decode decodes.\nfunc Decode(b []byte) error { return nil }\n\n'
          'func (r *Reader) Read() error { return nil }\n\nfunc parseInner(b []byte) {}\n')
GO_TEST = ('package wire\n\nimport "testing"\n\nfunc FuzzDecode(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, b []byte) {\n'
           '\t\tDecode(b)\n\t\t(&Reader{}).Read()\n\t})\n}\n')
REGISTRY = ('# test registry\nsrc/Core  XDecode  fuzz_x\n'
            'controller/internal/wire  Decode       FuzzDecode\n'
            'controller/internal/wire  Reader.Read  FuzzDecode\n')


def fuzz_tree(root, **changes):
    files = {
        'src/Core/X.c': CORE_C,
        'src/fuzz/fuzz_x.c': FUZZ_C,
        'src/fuzz/fuzz_common.c': '// shared\n',
        'src/fuzz/CMakeLists.txt': CMAKE,
        'src/fuzz/run_fuzzers.ps1': RUN_FUZZERS,
        'src/fuzz/corpus/fuzz_x/seed.bin': 'x',
        'controller/internal/wire/wire.go': GO_SRC,
        'controller/internal/wire/wire_test.go': GO_TEST,
        'ranz-bgp/go.mod': 'module example.com/ranz-bgp\n',
        '.github/quality/fuzz-targets.txt': REGISTRY,
    }
    files.update(changes)
    for path, text in files.items():
        if text is not None:
            write(root, path, text)


def test_fuzz_registry():
    def check(name, code, *texts, **changes):
        with tempfile.TemporaryDirectory() as root:
            fuzz_tree(root, **changes)
            expect('fuzz-registry: ' + name, run('fuzz-registry.py', 'check', '--root', root), code, *texts)

    check('every parser has a target', 0, 'has a fuzz target that runs in CI')
    check('a new C parser without a target', 1, 'XParseFrame looks like a parser',
          **{'src/Core/Y.c': 'UINT XParseFrame(const UCHAR *p,\n                 UINT size) {\n\treturn 0;\n}\n'})
    check('a static C parser is the entry point\'s', 0, 'has a fuzz target',
          **{'src/Core/Y.c': 'static UINT YParseFrame(const UCHAR *p) {\n\treturn 0;\n}\n'})
    check('a C prototype is no definition', 0, 'has a fuzz target', **{'src/Core/Y.c': 'UINT YParseFrame(const UCHAR *p);\n'})
    check('a new Go parser without a target', 1, 'ParseHeader looks like a parser',
          **{'controller/internal/wire/header.go': 'package wire\n\nfunc ParseHeader(s string) error { return nil }\n'})
    check('a new Go method parser without a target', 1, 'Conn.Receive looks like a parser',
          **{'ranz-bgp/internal/pipe/pipe.go': 'package pipe\n\nfunc (c Conn) Receive() {}\n'})
    check('an unexported Go parser is the entry point\'s', 0, 'has a fuzz target',
          **{'controller/internal/wire/header.go': 'package wire\n\nfunc parseHeader(s string) error { return nil }\n'})
    check('a parser in a Go test file is no parser', 0, 'has a fuzz target',
          **{'controller/internal/wire/x_test.go': 'package wire\n\nfunc ParseFixture(s string) {}\n'})
    check('an exempt function with its reason', 0, 'has a fuzz target',
          **{'src/Core/Y.c': 'bool YKeyOpen(const wchar_t *name) {\n\treturn true;\n}\n',
             '.github/quality/fuzz-targets.txt': REGISTRY + 'src/Core  YKeyOpen  exempt  opens a key by name\n'})
    check('an exempt function without a reason', 1, 'exempt without a reason',
          **{'src/Core/Y.c': 'bool YKeyOpen(const wchar_t *name) {\n\treturn true;\n}\n',
             '.github/quality/fuzz-targets.txt': REGISTRY + 'src/Core  YKeyOpen  exempt\n'})
    check('a stale line', 1, 'XGone is not a function of src/Core',
          **{'.github/quality/fuzz-targets.txt': REGISTRY + 'src/Core  XGone  fuzz_x\n'})
    check('a target that does not name the function', 1, 'fuzz_x.c does not name XOther',
          **{'src/Core/Y.c': 'bool XOther(void) {\n\treturn true;\n}\n',
             '.github/quality/fuzz-targets.txt': REGISTRY + 'src/Core  XOther  fuzz_x\n'})
    check('a target that names the entry point', 0, 'has a fuzz target',
          **{'src/Core/Y.c': 'bool XOther(void) {\n\treturn true;\n}\n',
             '.github/quality/fuzz-targets.txt': REGISTRY + 'src/Core  XOther  fuzz_x  via XDecode\n'})
    check('a missing C target', 1, 'fuzz_y.c does not exist',
          **{'.github/quality/fuzz-targets.txt': REGISTRY.replace('XDecode  fuzz_x', 'XDecode  fuzz_y')})
    check('a missing Go fuzz test', 1, 'no func FuzzOther',
          **{'.github/quality/fuzz-targets.txt': REGISTRY.replace('Decode       FuzzDecode', 'Decode       FuzzOther')})
    check('a C target that run_fuzzers.ps1 does not run', 1, 'not in the default -Targets',
          **{'src/fuzz/run_fuzzers.ps1': "param(\n\t[string[]] $Targets = @()\n)\n$MaxLen = @{ 'fuzz_x' = 4096 }\n"})
    check('a C target that CMake does not build', 1, 'not in RANZ_FUZZ_TARGETS',
          **{'src/fuzz/CMakeLists.txt': 'set(RANZ_FUZZ_TARGETS\n)\n'})
    check('a C target without seeds', 1, 'no seed corpus', **{'src/fuzz/corpus/fuzz_x/seed.bin': None,
                                                              'src/fuzz/corpus/fuzz_z/seed.bin': 'z'})
    check('a Go fuzz test that no line names', 1, 'FuzzLonely is listed for no function',
          **{'controller/internal/wire/lonely_test.go': 'package wire\n\nimport "testing"\n\nfunc FuzzLonely(f *testing.F) {}\n'})

    with tempfile.TemporaryDirectory() as root:
        fuzz_tree(root)
        expect('fuzz-registry: go-targets', run('fuzz-registry.py', 'go-targets', 'controller', '--root', root), 0,
               './internal/wire FuzzDecode')


def test_coverage_floor():
    floors = ('# test floors\nc  corea  80  src/Core/A*.c\nc  coreb  50  src/Core/B*.c\n'
              'go  controller/internal/x  60\ngo  controller/cmd/tool  0\n')

    def llvm(name, code, texts, files, floors_text=floors, scope_files=('A.c', 'Afoo.c', 'B.c')):
        with tempfile.TemporaryDirectory() as root:
            write(root, '.github/quality/coverage-floors.txt', floors_text)
            for f in scope_files:
                write(root, 'src/Core/' + f, '// x\n')
            export = {'data': [{'files': [{'filename': os.path.join(root, 'src', 'Core', n),
                                           'summary': {'lines': {'count': t, 'covered': c, 'percent': 0}}}
                                          for n, (c, t) in files.items()]}]}
            write(root, 'cov.json', json.dumps(export))
            expect('coverage-floor llvm: ' + name,
                   run('coverage-floor.py', 'llvm', '--export', os.path.join(root, 'cov.json'), '--root', root), code, *texts)

    llvm('modules at their floors', 0, ['| corea | 85 | 100 | 85.0% | 80.0% | ok |'],
         {'A.c': (45, 50), 'Afoo.c': (40, 50), 'B.c': (5, 10)})
    llvm('a module below its floor', 1, ['corea: 79.0% covered, below its floor of 80.0%'],
         {'A.c': (39, 50), 'Afoo.c': (40, 50), 'B.c': (5, 10)})
    llvm('a file of no module', 1, ['src/Core/C.c belongs to no C module'],
         {'A.c': (45, 50), 'Afoo.c': (40, 50), 'B.c': (5, 10), 'C.c': (1, 1)}, scope_files=('A.c', 'Afoo.c', 'B.c', 'C.c'))
    llvm('a module that did not run', 1, ['coreb: llvm-cov has no file'], {'A.c': (45, 50), 'Afoo.c': (40, 50)})

    def go(name, code, texts, profile, floors_text=floors):
        with tempfile.TemporaryDirectory() as root:
            write(root, '.github/quality/coverage-floors.txt', floors_text)
            write(root, 'controller/go.mod', 'module example.com/controller\n\ngo 1.26.0\n')
            write(root, 'cover.out', 'mode: atomic\n' + profile)
            expect('coverage-floor go: ' + name,
                   run('coverage-floor.py', 'go', '--module', 'controller', '--profile', os.path.join(root, 'cover.out'),
                       '--root', root), code, *texts)

    base = ('example.com/controller/internal/x/x.go:1.1,2.2 6 1\n'
            'example.com/controller/internal/x/x.go:3.1,4.2 4 0\n'
            'example.com/controller/internal/x/x.pb.go:3.1,4.2 100 0\n'
            'example.com/controller/cmd/tool/main.go:1.1,2.2 3 0\n')
    go('packages at their floors', 0, ['| controller/internal/x | 6 | 10 | 60.0% | 60.0% | ok |'], base)
    go('a block counted by two test binaries', 0, ['| controller/internal/x | 10 | 10 | 100.0%'],
       base + 'example.com/controller/internal/x/x.go:3.1,4.2 4 7\n')
    go('a package below its floor', 1, ['controller/internal/x: 50.0% covered, below its floor of 60.0%'],
       base.replace(':1.1,2.2 6 1', ':1.1,2.2 4 1'))
    go('a package without a floor', 1, ['controller/internal/y: 100.0% covered and no floor'],
       base + 'example.com/controller/internal/y/y.go:1.1,2.2 1 1\n')
    go('a floor of a package that is gone', 1, ['controller/cmd/tool: a floor', 'no coverage data'],
       base.replace('example.com/controller/cmd/tool/main.go:1.1,2.2 3 0\n', ''))


def test_bench_gate():
    medians = ('# test medians\nflood_fps_8 1000 frames/s 25\nexpire_1024 10 us 50\n')
    results = ('BENCH flood_fps_8 %s frames/s\nBENCH flood_fps_8_runs 1,2,3 frames/s\nBENCH expire_1024 %s us\n'
               'BENCH pack_bytes 7758 bytes\nBENCH new_case 5 ops/s\n')

    def compare(name, code, texts, fps, us, medians_text=medians):
        with tempfile.TemporaryDirectory() as root:
            write(root, 'medians.txt', medians_text)
            write(root, 'bench.txt', results % (fps, us))
            expect('bench-gate: ' + name, run('bench-gate.py', 'compare', '--medians', os.path.join(root, 'medians.txt'),
                                              os.path.join(root, 'bench.txt')), code, *texts)

    compare('within the margins', 0, ['2 benchmark cases within their margin', 'Not compared, no recorded median', 'new_case'],
            '850', '14')
    compare('a rate slower than its margin', 1, ['flood_fps_8: 790 frames/s, 26.6% slower'], '790', '10')
    compare('a time slower than its margin', 1, ['expire_1024: 16 us, 60.0% slower'], '1000', '16')
    compare('faster is no regression', 0, ['within their margin'], '5000', '1')
    compare('a recorded case that did not run', 1, ['gone_case: recorded'], '1000', '10',
            medians_text=medians + 'gone_case 3 ops/s 25\n')
    compare('a malformed median', 1, ['is not "<case> <median> <unit> <margin %>"'], '1000', '10',
            medians_text=medians + 'broken 0 ops/s 25\n')

    with tempfile.TemporaryDirectory() as root:
        runs = []
        for i, (fps, us) in enumerate([(1000, 10), (900, 11), (1100, 10), (500, 12), (1000, 2)]):
            path = os.path.join(root, 'run%d.txt' % i)
            write(root, 'run%d.txt' % i, 'BENCH a %d frames/s\nBENCH t %d us\nBENCH zero 0 ms\n' % (fps, us))
            runs.append(path)
        out = os.path.join(root, 'medians.txt')
        expect('bench-gate: record', run('bench-gate.py', 'record', '--out', out, *runs), 0)
        with open(out, encoding='utf-8') as f:
            text = f.read()
        # a: median 1000, slowest 500 is 100 % slower, margin 200; t: median 10, slowest 12 is 20 %
        # slower, margin 40; zero: left out
        for want in ('a 1000 frames/s 200\n', 't 10 us 40\n'):
            if want not in text:
                failures.append('bench-gate: record wrote no %r:\n%s' % (want, text))
        if '\nzero ' in text:
            failures.append('bench-gate: record kept a case with median 0:\n' + text)


def test_static_findings():
    tidy_log = ('C:\\w\\src\\Core\\Noise.c:120:5: warning: Value stored to \'n\' is never read [clang-analyzer-deadcode.DeadStores]\n'
                'C:\\w\\src\\Core\\Noise.c:200:1: note: some note\n'
                'C:\\w\\src\\Mayaqua\\Str.c:10:1: warning: outside the scope [bugprone-branch-clone]\n'
                '2 warnings generated.\n')
    msvc_log = ('C:\\w\\src\\Core\\Peer.c(88) : warning C6385: Reading invalid data from \'buf\'.: Lines: 80, 82, 88\n'
                'C:\\w\\src\\Core\\Peer.c(10): warning C4100: unreferenced formal parameter\n')
    key_tidy = "src/Core/Noise.c|clang-analyzer-deadcode.DeadStores|Value stored to 'n' is never read\n"
    key_msvc = "src/Core/Peer.c|C6385|Reading invalid data from 'buf'.\n"

    def check(name, code, texts, tool, log, baseline):
        with tempfile.TemporaryDirectory() as root:
            write(root, 'log.txt', log)
            write(root, 'baseline.txt', '# baseline\n' + baseline)
            expect('static-findings: ' + name, run('static-findings.py', '--tool', tool, '--log', os.path.join(root, 'log.txt'),
                                                   '--baseline', os.path.join(root, 'baseline.txt'), '--root', 'C:\\w'),
                   code, *texts)

    check('a new clang-tidy finding', 1, ['src/Core/Noise.c:120: Value stored', '1 new findings'], 'clang-tidy', tidy_log, '')
    check('a recorded clang-tidy finding', 0, ['No new clang-tidy finding (1 recorded'], 'clang-tidy', tidy_log, key_tidy)
    check('a moved finding keeps its key', 0, ['No new clang-tidy finding'], 'clang-tidy',
          tidy_log.replace('Noise.c:120:5', 'Noise.c:140:5'), key_tidy)
    check('a finding no longer found', 0, ['No longer found, take it out'], 'clang-tidy', '', key_tidy)
    check('a new /analyze finding', 1, ['src/Core/Peer.c:88: Reading invalid data', '[C6385]'], 'msvc', msvc_log, '')
    check('a recorded /analyze finding, other lines', 0, ['No new msvc finding'], 'msvc',
          msvc_log.replace('Lines: 80, 82, 88', 'Lines: 90, 92'), key_msvc)


if __name__ == '__main__':
    test_fuzz_registry()
    test_coverage_floor()
    test_bench_gate()
    test_static_findings()
    if failures:
        print('\n\n'.join(failures))
        print('%d fixtures failed' % len(failures))
        sys.exit(1)
    print('All quality gate fixtures passed')
