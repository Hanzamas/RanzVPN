# Fixtures for the scripts of the ADR-0040 quality gates: fuzz-registry.py, run_fuzzers.ps1 (its lines
# "// fuzz-reach:", with PowerShell 7), coverage-floor.py, bench-gate.py, static-findings.py and
# govulncheck-gate.py; for the guards of the start of ranz-node in service-eventlog.ps1 (the source scan of
# the VBScript firewall path and the checks of the firewall rules and of the script hosts, with PowerShell 7);
# and for the bound of every msiexec call of msi-install.ps1 (a planted hang, with PowerShell 7).
#
# Each gate runs on a throwaway tree or input made here and must pass what it should pass and fail
# what it should fail: a new parser without a fuzz target, a stale registry line, a fuzz target that
# CI would not run; a module below its floor or without one; a benchmark slower than its margin or
# missing; a new static analysis finding; a vulnerability that the code calls and nothing accepts.
# So a gate that passes everything fails here first.
#
# Usage: python -I quality-gates-test.py

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
failures = []


def run(script, *args):
    p = subprocess.run([sys.executable, '-I', os.path.join(HERE, script)] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={k: v for k, v in os.environ.items()
                                                                              if k not in ('GITHUB_ACTIONS', 'GITHUB_STEP_SUMMARY', 'GITHUB_WORKSPACE')})
    return p.returncode, p.stdout.decode('utf-8', errors='replace')


def expect(name, result, code, *texts, absent=()):
    got, out = result
    missing = [t for t in texts if t not in out]
    present = [t for t in absent if t in out]
    if got != code or missing or present:
        failures.append('%s: exit %d, want %d%s%s\n%s' % (name, got, code, ', missing %r' % missing if missing else '',
                                                        ', unwanted %r' % present if present else '', out))
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
FUZZ_C = ('// fuzz_x.c\n// libFuzzer target: XDecode\n//\n// fuzz-max-len: 4096\n'
          'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\tXDecode(data, size);\n\treturn 0;\n}\n')
CMAKE = ('file(GLOB RANZ_FUZZ_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS '
         '"${CMAKE_CURRENT_SOURCE_DIR}/fuzz_*.c")\nlist(REMOVE_ITEM RANZ_FUZZ_SOURCES "fuzz_common.c")\n')
RUN_FUZZERS = ("param(\n\t[string[]] $Targets = @()\n)\n"
               "if ($Targets.Count -eq 0) { $Targets = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'fuzz_*.c') }\n")
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
        'go.mod': 'module example.com/ranz\n',
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
    check('a run_fuzzers.ps1 with a list of targets', 1, 'has a default list of -Targets',
          **{'src/fuzz/run_fuzzers.ps1': RUN_FUZZERS + "param(\n\t[string[]] $Targets = @('fuzz_x')\n)\n"})
    check('a run_fuzzers.ps1 that does not find the targets', 1, "does not find the targets by -Filter 'fuzz_*.c'",
          **{'src/fuzz/run_fuzzers.ps1': "param(\n\t[string[]] $Targets = @()\n)\n"})
    check('a CMakeLists.txt that does not find the targets', 1, 'does not find the targets by file(GLOB',
          **{'src/fuzz/CMakeLists.txt': 'set(RANZ_FUZZ_TARGETS\n  fuzz_x\n)\n'})
    check('a C target without a max length', 1, 'src/fuzz/fuzz_x.c: no line "// fuzz-max-len: <bytes>"',
          **{'src/fuzz/fuzz_x.c': FUZZ_C.replace('// fuzz-max-len: 4096\n', '')})
    check('a max length that is no number', 1, 'no line "// fuzz-max-len: <bytes>"',
          **{'src/fuzz/fuzz_x.c': FUZZ_C.replace('4096', 'big')})
    check('a C target without seeds', 1, 'no seed corpus', **{'src/fuzz/corpus/fuzz_x/seed.bin': None,
                                                              'src/fuzz/corpus/fuzz_z/seed.bin': 'z'})
    # The lines "// fuzz-reach: <function>" (CORE-S5-6-R2, #557): one that names no function, and the lines of fuzz_peer
    reach = '// fuzz-max-len: 4096\n// fuzz-reach: %s\n'
    check('a fuzz-reach line that names a function', 0, 'has a fuzz target',
          **{'src/fuzz/fuzz_x.c': FUZZ_C.replace('// fuzz-max-len: 4096\n', reach % 'XDecode')})
    check('a fuzz-reach line that names no function', 1, 'src/fuzz/fuzz_x.c:5: a line "// fuzz-reach:" that names no function',
          **{'src/fuzz/fuzz_x.c': FUZZ_C.replace('// fuzz-max-len: 4096\n', reach % 'XDecode()')})
    check('a fuzz-reach line that names two functions', 1, 'src/fuzz/fuzz_x.c:5: a line "// fuzz-reach:" that names no function',
          **{'src/fuzz/fuzz_x.c': FUZZ_C.replace('// fuzz-max-len: 4096\n', reach % 'XDecode XParse')})
    peer = FUZZ_C.replace('fuzz_x.c', 'fuzz_peer.c')
    both = '// fuzz-reach: agent_dispatch_stun\n// fuzz-reach: agent_process_stun_binding\n'
    check('fuzz_peer with its fuzz-reach lines', 0, 'has a fuzz target',
          **{'src/fuzz/fuzz_peer.c': peer + both, 'src/fuzz/corpus/fuzz_peer/seed.bin': 'p'})
    check('fuzz_peer without its fuzz-reach lines', 1, 'src/fuzz/fuzz_peer.c: no line "// fuzz-reach: agent_dispatch_stun"',
          'src/fuzz/fuzz_peer.c: no line "// fuzz-reach: agent_process_stun_binding"',
          **{'src/fuzz/fuzz_peer.c': peer, 'src/fuzz/corpus/fuzz_peer/seed.bin': 'p'})
    check('fuzz_peer with one of its fuzz-reach lines gone', 1, 'no line "// fuzz-reach: agent_process_stun_binding"',
          **{'src/fuzz/fuzz_peer.c': peer + both.split('\n')[0] + '\n', 'src/fuzz/corpus/fuzz_peer/seed.bin': 'p'})
    check('a Go fuzz test that no line names', 1, 'FuzzLonely is listed for no function',
          **{'controller/internal/wire/lonely_test.go': 'package wire\n\nimport "testing"\n\nfunc FuzzLonely(f *testing.F) {}\n'})

    with tempfile.TemporaryDirectory() as root:
        fuzz_tree(root)
        expect('fuzz-registry: go-targets of a module in a directory', run('fuzz-registry.py', 'go-targets', 'controller', '--root', root), 0,
               './internal/wire FuzzDecode')
        # The module at the repository root names its packages by their path from the root
        expect('fuzz-registry: go-targets of the module at the root', run('fuzz-registry.py', 'go-targets', '.', '--root', root), 0,
               './controller/internal/wire FuzzDecode', absent=['src/Core', 'fuzz_x'])


def test_run_fuzzers():
    # run_fuzzers.ps1 of the tree on a throwaway src/fuzz, with a stand-in for the libFuzzer target fuzz_x that prints the
    # coverage of its seeds as libFuzzer does: a function that the seeds reach passes the replay, one that they miss fails
    # it, and a line "// fuzz-reach:" that names no function stops the run before the target runs (CORE-S5-6-R2, #557).
    # The stand-in is a shell script, so the fixtures run where the quality workflow runs them, on Linux.
    if os.name == 'nt':
        print('skip run_fuzzers: the stand-in of a target is a shell script')
        return
    pwsh = shutil.which('pwsh')
    if pwsh is None:
        failures.append('run_fuzzers: no pwsh on the PATH, which the fixtures of run_fuzzers.ps1 need')
        print('FAIL', 'run_fuzzers: no pwsh')
        return
    with open(os.path.join(ROOT, 'src', 'fuzz', 'run_fuzzers.ps1'), encoding='utf-8') as f:
        script = f.read()
    fuzzer = '#!/bin/sh\necho "COVERED_FUNC: hits: 1 edges: 1/2 XDecode x.c:1"\necho "UNCOVERED_FUNC: hits: 0 edges: 0/2 XOther x.c:9"\n' \
             'echo "NO MEMORY LEAKS"\n'

    def check(name, code, texts, line, absent=()):
        with tempfile.TemporaryDirectory() as root:
            write(root, 'src/fuzz/run_fuzzers.ps1', script)
            write(root, 'src/fuzz/fuzz_x.c', FUZZ_C + line)
            write(root, 'src/fuzz/corpus/fuzz_x/seed.bin', 'x')
            write(root, 'build/fuzz_x.exe', fuzzer)
            os.chmod(os.path.join(root, 'build', 'fuzz_x.exe'), 0o755)
            p = subprocess.run([pwsh, '-NoProfile', '-NonInteractive', '-File', os.path.join(root, 'src', 'fuzz', 'run_fuzzers.ps1'),
                                '-BuildDir', os.path.join(root, 'build'), '-Seconds', '0'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            expect('run_fuzzers: ' + name, (p.returncode, p.stdout.decode('utf-8', errors='replace')), code, *texts, absent=absent)

    check('a function that the seeds reach', 0, ['the seeds reach XDecode', 'All fuzz targets passed'], '// fuzz-reach: XDecode\n')
    check('a function that no seed reaches', 1, ['no seed reaches XOther (fuzz-reach)'], '// fuzz-reach: XOther\n')
    check('a fuzz-reach line that names no function', 1, ["'// fuzz-reach: XDecode()' is not a line '// fuzz-reach: <function>'"],
          '// fuzz-reach: XDecode()\n', absent=['All fuzz targets passed', 'the seeds reach'])


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

    # The module at the repository root (ONE-1): its packages are named by their path from the root
    def go_root(name, code, texts, profile):
        with tempfile.TemporaryDirectory() as root:
            write(root, '.github/quality/coverage-floors.txt', floors)
            write(root, 'go.mod', 'module example.com/ranz\n\ngo 1.26.0\n')
            write(root, 'cover.out', 'mode: atomic\n' + profile)
            expect('coverage-floor go, module at the root: ' + name,
                   run('coverage-floor.py', 'go', '--module', '.', '--profile', os.path.join(root, 'cover.out'),
                       '--root', root), code, *texts)

    root_base = base.replace('example.com/controller/', 'example.com/ranz/controller/')
    go_root('packages at their floors', 0, ['| controller/internal/x | 6 | 10 | 60.0% | 60.0% | ok |'], root_base)
    go_root('a package below its floor', 1, ['controller/internal/x: 50.0% covered, below its floor of 60.0%'],
            root_base.replace(':1.1,2.2 6 1', ':1.1,2.2 4 1'))
    go_root('a package of the other tree without a floor', 1, ['ranz-bgp/internal/y: 100.0% covered and no floor'],
            root_base + 'example.com/ranz/ranz-bgp/internal/y/y.go:1.1,2.2 1 1\n')
    go_root('a floor of a package that is gone', 1, ['controller/cmd/tool: a floor', 'no coverage data'],
            root_base.replace('example.com/ranz/controller/cmd/tool/main.go:1.1,2.2 3 0\n', ''))


def test_bench_gate():
    # A rate, a time of 200 us, a time of 2 us (under 50 us) and a time of 50 us (not under it)
    medians = ('# test medians\nflood_fps_8 1000 frames/s 25\nexpire_1024 200 us 50\ntiny_expire 2 us 100\nmid_case 50 us 25\n')
    template = ('BENCH flood_fps_8 %s frames/s\nBENCH flood_fps_8_runs 1,2,3 frames/s\nBENCH expire_1024 %s us\n'
                'BENCH tiny_expire %s us\nBENCH mid_case %s us\nBENCH pack_bytes 7758 bytes\nBENCH new_case 5 ops/s\n')

    def bench(fps='1000', us='200', tiny='2', mid='50'):
        # The text of one result file, one run of the benchmark
        return template % (fps, us, tiny, mid)

    def compare(name, code, texts, results, medians_text=medians, gate_args=(), wildcard=False):
        # results: the text of one result file per run
        with tempfile.TemporaryDirectory() as root:
            write(root, 'medians.txt', medians_text)
            paths = []
            for i, text in enumerate(results):
                write(root, 'bench-run%d.txt' % i, text)
                paths.append(os.path.join(root, 'bench-run%d.txt' % i))
            if wildcard:
                paths = [os.path.join(root, 'bench-run*.txt')]
            expect('bench-gate: ' + name, run('bench-gate.py', 'compare', '--medians', os.path.join(root, 'medians.txt'),
                                              *gate_args, *paths), code, *texts)

    compare('within the margins', 0, ['4 benchmark cases within their margin', 'Not compared, no recorded median', 'new_case'],
            [bench(fps='850', us='220')])
    compare('a rate slower than its margin', 1, ['flood_fps_8: 790 frames/s, 26.6% slower'], [bench(fps='790')])
    compare('a time slower than its margin', 1, ['expire_1024: 320 us, 60.0% slower'], [bench(us='320')])
    compare('faster is no regression', 0, ['within their margin'], [bench(fps='5000', us='1', tiny='1', mid='1')])
    compare('a recorded case that did not run', 1, ['gone_case: recorded'], [bench()],
            medians_text=medians + 'gone_case 3 ops/s 25\n')
    compare('a malformed median', 1, ['is not "<case> <median> <unit> <margin %>"'], [bench()],
            medians_text=medians + 'broken 0 ops/s 25\n')

    # The best of the runs is judged: a run that a busy machine slowed is noise, a slowdown that every run shows is real
    compare('one slow run in three is noise', 0, ['within their margin of the recorded median (best of 3 runs)'],
            [bench(fps='700', us='400'), bench(fps='990', us='210'), bench(fps='600', us='350')], gate_args=('--runs', '3'))
    compare('the best run counts, not the first', 0, ['best of 3 runs'],
            [bench(fps='100', us='900'), bench(fps='100', us='900'), bench(fps='1000', us='200')])
    compare('a rate that every run shows slower fails', 1, ['flood_fps_8: 760 frames/s, 31.6% slower'],
            [bench(fps='700'), bench(fps='760'), bench(fps='730')], gate_args=('--runs', '3'))
    compare('a time that every run shows slower fails', 1, ['expire_1024: 330 us, 65.0% slower'],
            [bench(us='400'), bench(us='330'), bench(us='350')], gate_args=('--runs', '3'))
    compare('fewer result files than the runs asked for', 1, ['1 result files given, and the gate judges the best of 3 runs'],
            [bench()], gate_args=('--runs', '3'))
    compare('a wildcard names every result file', 0, ['best of 3 runs'],
            [bench(fps='100'), bench(fps='990'), bench(fps='100')], wildcard=True)
    compare('a wildcard that names no file', 1, ['no result file matches'], [], wildcard=True)

    # A time case whose recorded median is under 50 us fails only when it is slower by more than 100 us
    compare('a time under 50 us is not judged by its margin', 0, ['ok, under 50 us'], [bench(tiny='6')])
    compare('a time under 50 us that is 100 us slower passes', 0, ['within their margin'], [bench(tiny='102')])
    compare('a time under 50 us that is more than 100 us slower fails', 1,
            ['tiny_expire: 105 us, 103 us slower than the recorded median 2 us'], [bench(tiny='105')])
    compare('a time of 50 us keeps its margin', 1, ['mid_case: 70 us, 40.0% slower'], [bench(mid='70')])
    compare('a time under 50 us in milliseconds, passing', 0, ['within their margin'], [bench() + 'BENCH tiny_ms 0.1 ms\n'],
            medians_text=medians + 'tiny_ms 0.04 ms 50\n')
    compare('a time under 50 us in milliseconds, failing', 1, ['tiny_ms: 0.2 ms, 160 us slower than the recorded median 0.04 ms'],
            [bench() + 'BENCH tiny_ms 0.2 ms\n'], medians_text=medians + 'tiny_ms 0.04 ms 50\n')

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

    def check(name, code, texts, tool, log, baseline, options=()):
        with tempfile.TemporaryDirectory() as root:
            write(root, 'log.txt', log)
            write(root, 'baseline.txt', '# baseline\n' + baseline)
            expect('static-findings: ' + name, run('static-findings.py', '--tool', tool, '--log', os.path.join(root, 'log.txt'),
                                                   '--baseline', os.path.join(root, 'baseline.txt'), '--root', 'C:\\w', *options),
                   code, *texts)

    check('a new clang-tidy finding', 1, ['src/Core/Noise.c:120: Value stored', '1 new findings'], 'clang-tidy', tidy_log, '')
    check('a recorded clang-tidy finding', 0, ['No new clang-tidy finding (1 recorded'], 'clang-tidy', tidy_log, key_tidy)
    check('a moved finding keeps its key', 0, ['No new clang-tidy finding'], 'clang-tidy',
          tidy_log.replace('Noise.c:120:5', 'Noise.c:140:5'), key_tidy)
    check('a finding no longer found', 0, ['No longer found 1 of 1 times, take it out'], 'clang-tidy', '', key_tidy)
    check('a recorded finding at a second line', 1, ['src/Core/Noise.c:120, src/Core/Noise.c:300: Value stored',
                                                     'found 2 times, recorded 1'], 'clang-tidy',
          tidy_log + tidy_log.replace('Noise.c:120:5', 'Noise.c:300:5'), key_tidy)
    check('a header line that two files report is one finding', 0, ['No new clang-tidy finding'], 'clang-tidy',
          tidy_log + tidy_log, key_tidy)
    check('a new /analyze finding', 1, ['src/Core/Peer.c:88: Reading invalid data', '[C6385]'], 'msvc', msvc_log, '')
    check('a recorded /analyze finding, other lines', 0, ['No new msvc finding'], 'msvc',
          msvc_log.replace('Lines: 80, 82, 88', 'Lines: 90, 92'), key_msvc)
    juice_log = msvc_log + 'C:\\w\\src\\Core\\3rdparty\\libjuice\\src\\agent.c(120) : warning C6011: Dereferencing NULL pointer \'a\'.\n'
    check('a third-party finding in the scope', 1, ['src/Core/3rdparty/libjuice/src/agent.c:120: Dereferencing NULL pointer'],
          'msvc', juice_log, key_msvc)
    check('a third-party finding under --exclude', 0, ['No new msvc finding'], 'msvc', juice_log, key_msvc,
          options=('--scope', 'src/Core', '--exclude', 'src/Core/3rdparty'))


def test_govulncheck_gate():
    def finding(osv, module, version, function=None):
        top = {'module': module, 'version': version, 'package': module + '/pkg'}
        if function:
            top['function'] = function
        own = {'module': 'example.com/own', 'package': 'example.com/own/x', 'function': 'Run',
               'position': {'filename': 'x/run.go', 'line': 3}}
        return {'finding': {'osv': osv, 'fixed_version': 'v1.1.0', 'trace': [top, own] if function else [top]}}

    stream = [{'config': {'scanner_name': 'govulncheck'}},
              {'osv': {'id': 'GO-1', 'summary': 'crash in parser'}},
              {'osv': {'id': 'GO-2', 'summary': 'race in server'}},
              finding('GO-1', 'example.com/dep', 'v1.0.0', 'Parse'),
              finding('GO-1', 'example.com/dep', 'v1.0.0', 'Parse'),
              finding('GO-3', 'example.com/other', 'v2.0.0')]
    accepted = '# test\nGO-1 example.com/dep@v1.0.0 fixed upstream, verified\n'

    def check(name, code, texts, messages, accepted_text=accepted, absent=()):
        with tempfile.TemporaryDirectory() as root:
            write(root, 'accepted.txt', accepted_text)
            # Indented objects one after another, as govulncheck -format json writes them
            write(root, 'vuln.json', '\n'.join(json.dumps(m, indent=2) for m in messages) + '\n')
            expect('govulncheck-gate: ' + name, run('govulncheck-gate.py', '--accepted', os.path.join(root, 'accepted.txt'),
                                                    os.path.join(root, 'vuln.json')), code, *texts, absent=absent)

    check('an accepted vulnerability', 0, ['Accepted: GO-1 in example.com/dep@v1.0.0', 'Not called by the code: GO-3'], stream)
    check('a called vulnerability', 1, ['GO-2 in example.com/dep@v1.0.0: race in server', 'reaches Serve from x/run.go Run'],
          stream + [finding('GO-2', 'example.com/dep', 'v1.0.0', 'Serve')])
    check('an accepted entry of another version', 1, ['GO-1 in example.com/dep@v1.0.0: crash in parser'], stream,
          accepted_text='GO-1 example.com/dep@v0.9.0 fixed upstream\n')
    check('an accepted entry no longer found', 0, ['No longer found, take it out', 'GO-9'], stream,
          accepted_text=accepted + 'GO-9 example.com/gone@v1.0.0 gone\n')

    # The modules of the scan, as the SBOM message of govulncheck lists them: the accepted file is shared by
    # controller/ and ranz-bgp/, so an entry of a module that this scan does not have is the other one's
    sbom = {'SBOM': {'go_version': 'go1.27.3', 'modules': [{'path': 'example.com/own'},
                                                          {'path': 'example.com/dep', 'version': 'v1.0.0'},
                                                          {'path': 'example.com/other', 'version': 'v2.0.0'}]}}
    check('an accepted entry of a module in the scan, no longer found', 0,
          ['No longer found, take it out', 'GO-8 example.com/other@v1.0.0', 'GO-7 stdlib@v1.27.2'], [sbom] + stream,
          accepted_text=accepted + 'GO-8 example.com/other@v1.0.0 fixed in v2.0.0\nGO-7 stdlib@v1.27.2 fixed in go1.27.3\n')
    check('an accepted entry of a module outside the scan', 0, ['For a module outside this scan: GO-9 example.com/gone@v1.0.0'],
          [sbom] + stream, accepted_text=accepted + 'GO-9 example.com/gone@v1.0.0 the other module\'s\n',
          absent=['No longer found'])


def test_one_binary():
    # CI, WiX packages and docs that name an executable of the two programs that ranz replaced (ONE-1, #310)
    clean = {'.github/workflows/ranz.yml': 'go build -o build ./controller/cmd/ranz\n',
             'docs/adr/0026.md': 'the service `ranz-controller` runs `ranz controller`, and `ranz bgp` is the sidecar\n',
             'ranz-bgp/installer/other.txt': 'ranz-bgp.exe outside the scope is not read\n'}

    def check(name, code, texts, files=None):
        with tempfile.TemporaryDirectory() as root:
            for path, text in {**clean, **(files or {})}.items():
                write(root, path, text)
            expect('one-binary: ' + name, run('one-binary-check.py', '--root', root), code, *texts)

    check('a tree with the one executable', 0, ['name no executable'])
    check('a workflow that runs an old executable', 1, ['ranz-bgp.exe', 'the file name of an executable'],
          {'.github/workflows/old.yml': 'run: build\\ranz-bgp.exe -version\n'})
    check('a script that builds an old main package', 1, ['cmd/ranz-controller', 'the path of a main package'],
          {'.github/scripts/build.ps1': 'go build ./cmd/ranz-controller\n'})
    check('a doc that runs an old program', 1, ['ranz-controller reset-admin', 'a command line of a program'],
          {'docs/guide.md': 'run ranz-controller reset-admin on the host\n'})
    check('a WiX package that names an old executable', 1, ['ranz-controller.exe'],
          {'installer/Ranz.wxs': '<File Name="ranz-controller.exe" />\n'})
    check('the checker itself is not read', 0, ['name no executable'],
          {'.github/scripts/one-binary-check.py': 'ranz-bgp.exe\n'})


def test_service_eventlog():
    # service-eventlog.ps1 (CORE-S8-1-R1, #575) guards the start of ranz-node, as firewall-rule.ps1 guarded that of vpnserver:
    # no VBScript firewall path in the sources (ticket #47, criterion 5), and, in windows.yml, no firewall rule changed by a
    # restart of the service and no cscript or wscript started by it (criterion 2). The scan runs here on throwaway trees with
    # a planted line, and the checks of the rules and of the script hosts on planted data (-SelfTest): each must fail on its
    # fault. The part that needs Windows, the service, the rules of Windows Firewall and the ETW trace, plants a real rule and a
    # real process start in windows.yml. PowerShell 7 runs the script here, on Linux.
    pwsh = shutil.which('pwsh')
    if pwsh is None:
        failures.append('service-eventlog: no pwsh on the PATH, which the fixtures of service-eventlog.ps1 need')
        print('FAIL', 'service-eventlog: no pwsh')
        return
    script = os.path.join(HERE, 'service-eventlog.ps1')

    def run_script(*args):
        p = subprocess.run([pwsh, '-NoProfile', '-NonInteractive', '-File', script] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        return p.returncode, p.stdout.decode('utf-8', errors='replace')

    sources = ('src/Mayaqua', 'src/Cedar', 'src/Core', 'src/ranz-node')

    def scan(name, code, files=None, texts=(), absent=(), folders=sources):
        # A tree with a clean source file in each folder of the scan, and the files of the fixture
        with tempfile.TemporaryDirectory() as root:
            for folder in folders:
                write(root, folder + '/Clean.c', '// nothing of the old path\n')
            for path, text in (files or {}).items():
                write(root, path, text)
            expect('service-eventlog scan: ' + name, run_script('-ScanRoot', root), code, *texts, absent=absent)

    scan('sources that name no VBScript path', 0, texts=['name no VBScript firewall path (4 files in src/Mayaqua, src/Cedar, src/Core, src/ranz-node)'])
    # The seven things that the VBScript firewall path of the old server was made of, each in a line of its own
    planted = {
        'cscript': 'Win32Run("cscript.exe", script);',
        'wscript': 'Win32Run(L"wscript.exe", script);',
        'a .vbs file': 'StrCpy(name, size, "detectvm.vbs");',
        'winfire_': 'Format(name, size, "winfire_%u", pid);',
        'FW ScriptHash': '#define KEY "FW ScriptHash"',
        'SOFTETHER_FW_SCRIPT_HASH': 'MsRegWriteInt(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, hash, 1);',
        'RegistWindowsFirewall': 'MsRegistWindowsFirewall();',
    }
    for what, line in planted.items():
        scan('a line that names ' + what, 1, {'src/Cedar/Planted.c': line + '\n'},
             texts=['Planted.c:1: ' + line, 'lines of the sources of the Node name the VBScript firewall path'], absent=['name no VBScript firewall path'])
    scan('a line that names it in capitals', 1, {'src/Mayaqua/Planted.c': 'run("CScript.EXE");\n'}, texts=['Planted.c:1: run("CScript.EXE");'])
    scan('a line in a header of the program', 1, {'src/ranz-node/Planted.h': '#define HOST "wscript.exe"\n'}, texts=['Planted.h:1:'])
    scan('a line in the new core', 1, {'src/Core/Planted.c': '// cscript\n'}, texts=['Planted.c:1:'])
    scan('a line in the code of a third party', 0, {'src/Mayaqua/3rdparty/lib/Skip.c': 'run("cscript.exe");\n'},
         texts=['name no VBScript firewall path'], absent=['Skip.c'])
    scan('a line in a file that is no source', 0, {'src/Cedar/notes.txt': 'cscript\n'}, texts=['name no VBScript firewall path'])
    scan('a folder that is not there', 1, folders=('src/Mayaqua', 'src/Cedar', 'src/ranz-node'), texts=['the source scan has no folder src/Core'])
    scan('no source file at all', 1, {folder + '/readme.txt': 'x\n' for folder in sources}, folders=(),
         texts=['the source scan found no .c or .h file'])

    expect('service-eventlog: the checks of the rules and of the script hosts fail on their planted faults', run_script('-SelfTest'), 0,
           'ok: the check passes the same rules',
           'ok: the check fails on a rule that was added',
           'ok: the check fails on a rule that was deleted',
           'ok: the check fails on a rule that was changed',
           'ok: the check passes a program that started no script host',
           'ok: the check fails on a cscript.exe that the program started',
           'ok: the check fails on a WScript.EXE that the program started',
           'ok: the check fails on a trace that holds no start of the program')


def test_msi_install():
    # msi-install.ps1 (CI-FLAKE-6, #593) gives every msiexec call a bound: a call that never ends fails its step after 300 s with the
    # evidence, and its process tree is ended, where it held the job for 55 minutes in three runs. -SelfTest plants the hang: a
    # stand-in for msiexec.exe that never ends and starts a child that never ends either, run through Invoke-Msiexec with a bound of
    # 20 s. The call must fail within it, naming the verb and the package, with the evidence printed and kept, and both processes
    # must be ended; a call with no bound returns after the 120 s that the stand-in sleeps, and the fixture fails on that. The same
    # check runs on Windows, on x64 and arm64, in the msi jobs of windows.yml, with the real msiexec.exe and the process list of
    # the evidence. PowerShell 7 runs the script here, on Linux.
    pwsh = shutil.which('pwsh')
    if pwsh is None:
        failures.append('msi-install: no pwsh on the PATH, which the self-test of msi-install.ps1 needs')
        print('FAIL', 'msi-install: no pwsh')
        return
    script = os.path.join(HERE, 'msi-install.ps1')
    try:
        p = subprocess.run([pwsh, '-NoProfile', '-NonInteractive', '-File', script, '-SelfTest'], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=300)
        result = (p.returncode, p.stdout.decode('utf-8', errors='replace'))
    except subprocess.TimeoutExpired as e:
        result = (-1, (e.stdout or b'').decode('utf-8', errors='replace') + '\nthe self-test did not end within 300 s')
    expect('msi-install: a msiexec that never ends fails within its bound, with the evidence, and its process tree is ended', result, 0,
           'ok: a call that ends gives its exit code, and leaves no evidence of a hang',
           'ok: a msiexec that never ends fails within its bound (20 s, after ',
           'and the failure names the verb and the package',
           'ok: the evidence holds the processes, the end of the verbose log, the events of Windows Installer and the state of msiserver, and is kept in a file',
           'ok: the process tree of the call is ended: the stand-in and its child')


if __name__ == '__main__':
    test_fuzz_registry()
    test_run_fuzzers()
    test_coverage_floor()
    test_bench_gate()
    test_static_findings()
    test_govulncheck_gate()
    test_one_binary()
    test_service_eventlog()
    test_msi_install()
    if failures:
        print('\n\n'.join(failures))
        print('%d fixtures failed' % len(failures))
        sys.exit(1)
    print('All quality gate fixtures passed')
