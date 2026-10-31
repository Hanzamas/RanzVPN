# The fuzz target gate of ADR-0040 item 1: every parser or wire-format handler of the new core has a
# fuzz target, and every fuzz target runs in CI.
#
# A function looks like a parser or wire-format handler when one of the words of its name (split at
# the capitals: PeerSignalDecode is Peer, Signal, Decode) is one of PARSER_WORDS. The functions looked
# at are the exported ones of the new core:
# - C: every function that is not static in the .c files of C_SCOPE;
# - Go: every exported function and method in the non-test .go files of GO_SCOPE, generated code
#   (*.pb.go) left out. A method is named <type>.<method>, Conn.Read.
#
# .github/quality/fuzz-targets.txt lists each such function, one per line:
#   <directory> <function> <target> [via <entry point>]
#   <directory> <function> exempt <reason>
# <target> is a libFuzzer target of src/fuzz (fuzz_noise) for C, a Go fuzz test (FuzzOpen in a
# _test.go file of <directory>) for Go. The target's source must name the function, or <entry point>
# when the target reaches the function through it. A function that is not a parser despite its name
# is exempt, with the reason. A line may also list a parser whose name has none of the words.
#
# The check fails for:
# - a function that looks like a parser and has no line (a new parser without a fuzz target);
# - a line whose function no longer exists, or whose target does not exist or does not name it;
# - a C target that has no line "// fuzz-max-len: <bytes>" for run_fuzzers.ps1's -max_len, or no seed
#   corpus; and a src/fuzz/CMakeLists.txt or run_fuzzers.ps1 that does not find the targets by their
#   file names (fuzz_*.c), so that CI would not build or run a new one: a target is a new file and
#   is in no list;
# - a line "// fuzz-reach:" of a C target that names no function, which run_fuzzers.ps1 refuses, and a
#   target of REACH without its lines "// fuzz-reach: <function>": without them run_fuzzers.ps1 would no
#   longer check that the seeds reach those functions, and say nothing (CORE-S5-6-R2, #557);
# - a Go fuzz test of GO_SCOPE that no line names, which CI would never run (CI runs the targets of
#   this file: the go-targets mode).
#
# Usage:
#   python fuzz-registry.py [check] [--root DIR]  the check above; exit 1 on any problem
#   python fuzz-registry.py go-targets MODULE     the Go fuzz tests of the module in the directory MODULE
#                                                 ("." for the module at the repository root, which
#                                                 holds controller/ and ranz-bgp/), one
#                                                 "<package> <test>" per line, for go test -fuzz
#
# Standard library only.

import argparse
import os
import re
import sys

C_SCOPE = ['src/Core', 'src/Cedar/Node*.c', 'src/Cedar/ConfigStore*.c']
GO_SCOPE = ['controller', 'ranz-bgp']
PARSER_WORDS = {'Parse', 'Decode', 'Unmarshal', 'Deserialize', 'Read', 'Receive', 'Recv', 'Input', 'Open', 'Import',
                'Classify', 'Unseal', 'Unpack'}

REGISTRY = '.github/quality/fuzz-targets.txt'
FUZZ_DIR = 'src/fuzz'

# The functions that the seeds of a C target must reach, each named in a line "// fuzz-reach: <function>" of the target,
# which run_fuzzers.ps1 checks in the coverage of the replay of the seeds. fuzz_peer reaches the dispatch of a STUN
# message by libjuice and the processing of a check whose MESSAGE-INTEGRITY holds (CORE-S5-6-R1 #537, CORE-S5-6-R2 #557).
REACH = {'fuzz_peer': ('agent_dispatch_stun', 'agent_process_stun_binding')}

_WORD_RE = re.compile(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+')
# A C function head at the start of a line: return type, name and '('; the definition is the head
# whose first '{' comes before its first ';'
_C_HEAD_RE = re.compile(r'^(?!static\b|typedef\b|extern\b|return\b|else\b|if\b|for\b|while\b|switch\b|do\b)'
                        r'[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\(', re.M)
_GO_FUNC_RE = re.compile(r'^func\s+(?:\(\s*(?:\w+\s+)?\*?\s*([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*\)\s*)?([A-Za-z_]\w*)\s*[\[(]', re.M)
_GO_FUZZ_RE = re.compile(r'^func\s+(Fuzz\w*)\s*\(\s*\w+\s+\*testing\.F\s*\)', re.M)


def words(name):
    return _WORD_RE.findall(name)


def looks_like_parser(name):
    return any(w in PARSER_WORDS for w in words(name))


def read(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read()


def strip_c_comments(text):
    # Comments and string literals blanked, so a head inside them is not taken for code
    def blank(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:[^"\\\n]|\\.)*"', blank, text, flags=re.S)


def c_files(root):
    out = []
    for entry in C_SCOPE:
        directory, _, pattern = entry.rpartition('/') if entry.endswith('.c') else (entry, '', '*.c')
        regex = re.compile('^' + re.escape(pattern).replace(r'\*', '.*') + '$')
        full = os.path.join(root, directory)
        if not os.path.isdir(full):
            continue
        for name in sorted(os.listdir(full)):
            if regex.match(name) and os.path.isfile(os.path.join(full, name)):
                out.append((directory, directory + '/' + name))
    return out


def c_functions(text):
    # The names of the functions that a C file defines and does not make static
    code = strip_c_comments(text)
    names = []
    for m in _C_HEAD_RE.finditer(code):
        rest = code[m.end():]
        brace, semi = rest.find('{'), rest.find(';')
        if brace >= 0 and (semi < 0 or brace < semi):
            names.append(m.group(1))
    return names


def go_files(root, module, tests):
    out = []
    for base, dirs, files in os.walk(os.path.join(root, module)):
        dirs[:] = sorted(d for d in dirs if d not in ('testdata', 'vendor') and not d.startswith('.'))
        for name in sorted(files):
            if not name.endswith('.go') or name.endswith('.pb.go') or name.endswith('_test.go') != tests:
                continue
            path = os.path.join(base, name)
            out.append((os.path.relpath(base, root).replace(os.sep, '/'), path))
    return out


def go_functions(text):
    # Exported functions as Name, exported methods of exported or unexported types as Type.Name
    names = []
    for m in _GO_FUNC_RE.finditer(text):
        receiver, name = m.group(1), m.group(2)
        if not name[0].isupper():
            continue
        names.append(receiver + '.' + name if receiver else name)
    return names


def parse_registry(path):
    entries, problems = [], []
    for number, line in enumerate(read(path).splitlines(), 1):
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        where = '%s:%d' % (REGISTRY, number)
        if len(fields) < 3:
            problems.append('%s: "%s" is not "<directory> <function> <target> [via <entry point>]" '
                            'or "<directory> <function> exempt <reason>"' % (where, line))
            continue
        entry = {'dir': fields[0], 'func': fields[1], 'target': fields[2], 'via': None, 'where': where}
        if fields[2] == 'exempt':
            if len(fields) < 4:
                problems.append('%s: %s is exempt without a reason' % (where, fields[1]))
            entry['target'] = None
        elif len(fields) == 5 and fields[3] == 'via':
            entry['via'] = fields[4]
        elif len(fields) != 3:
            problems.append('%s: "%s": after the target only "via <entry point>" may follow' % (where, line))
        entries.append(entry)
    return entries, problems


def cmake_takes_every_source(root):
    # Does src/fuzz/CMakeLists.txt find the targets with file(GLOB ... fuzz_*.c)?
    text = read(os.path.join(root, FUZZ_DIR, 'CMakeLists.txt'))
    return re.search(r'file\(\s*GLOB\b[^)]*fuzz_\*\.c', text) is not None


def run_fuzzers_finds_targets(root):
    # (finds every fuzz_*.c itself, has a default list of targets that a new one would have to be added to)
    text = read(os.path.join(root, FUZZ_DIR, 'run_fuzzers.ps1'))
    finds = re.search(r"-Filter\s+'fuzz_\*\.c'", text) is not None
    listed = re.search(r"\$Targets\s*=\s*@\(\s*'fuzz_", text) is not None
    return finds, listed


def max_len_of(path):
    # The -max_len of a target: the number of its line "// fuzz-max-len: <bytes>", None without one
    m = re.search(r'^//\s*fuzz-max-len:\s*(\d+)\s*$', read(path), re.M)
    return int(m.group(1)) if m else None


def reach_of(path):
    # The functions of the lines "// fuzz-reach: <function>" of a target, and the numbers of its lines that start with
    # "// fuzz-reach:" and name no function, as run_fuzzers.ps1 reads them
    functions, malformed = [], []
    for number, line in enumerate(read(path).splitlines(), 1):
        if re.match(r'//\s*fuzz-reach:', line):
            m = re.match(r'//\s*fuzz-reach:\s*(\w+)\s*$', line)
            if m:
                functions.append(m.group(1))
            else:
                malformed.append(number)
    return functions, malformed


def names_word(text, word):
    return re.search(r'(?<![\w])' + re.escape(word) + r'(?![\w])', text) is not None


def check(root):
    problems = []
    registry = os.path.join(root, REGISTRY)
    if not os.path.isfile(registry):
        return ['%s does not exist' % REGISTRY]
    entries, problems = parse_registry(registry)
    listed = {(e['dir'], e['func']) for e in entries}

    # The functions that exist, and those that look like parsers
    exists = set()
    candidates = []
    for directory, path in c_files(root):
        for name in c_functions(read(os.path.join(root, path))):
            exists.add((directory, name))
            if looks_like_parser(name):
                candidates.append((directory, name, path))
    for module in GO_SCOPE:
        for directory, path in go_files(root, module, tests=False):
            for name in go_functions(read(path)):
                exists.add((directory, name))
                if looks_like_parser(name.rsplit('.', 1)[-1]):
                    candidates.append((directory, name, os.path.relpath(path, root).replace(os.sep, '/')))

    for directory, name, path in candidates:
        if (directory, name) not in listed:
            word = next(w for w in words(name.rsplit('.', 1)[-1]) if w in PARSER_WORDS)
            problems.append('%s: %s looks like a parser or wire-format handler (its name has "%s") and has no line '
                            'in %s: add a fuzz target that drives it and list it there, or list it as exempt with '
                            'the reason it is not one (ADR-0040 item 1)' % (path, name, word, REGISTRY))

    # The fuzz targets that exist
    go_fuzz = {}
    for module in GO_SCOPE:
        for directory, path in go_files(root, module, tests=True):
            text = read(path)
            for m in _GO_FUZZ_RE.finditer(text):
                go_fuzz[(directory, m.group(1))] = text

    named_go = set()
    for e in entries:
        key = (e['dir'], e['func'])
        if key not in exists:
            problems.append('%s: %s is not a function of %s (exported, or not static in C): a stale line'
                            % (e['where'], e['func'], e['dir']))
        if e['target'] is None:
            continue
        name = e['via'] or e['func'].rsplit('.', 1)[-1]
        if e['target'].startswith('fuzz_'):
            source = os.path.join(root, FUZZ_DIR, e['target'] + '.c')
            if not os.path.isfile(source):
                problems.append('%s: %s/%s.c does not exist' % (e['where'], FUZZ_DIR, e['target']))
                continue
            if not names_word(read(source), name):
                problems.append('%s: %s/%s.c does not name %s' % (e['where'], FUZZ_DIR, e['target'], name))
        elif e['target'].startswith('Fuzz'):
            text = go_fuzz.get((e['dir'], e['target']))
            if text is None:
                problems.append('%s: no func %s(f *testing.F) in a _test.go file of %s' % (e['where'], e['target'], e['dir']))
                continue
            named_go.add((e['dir'], e['target']))
            if not names_word(text, name):
                problems.append('%s: the test file of %s does not name %s' % (e['where'], e['target'], name))
        else:
            problems.append('%s: the target %s is neither a libFuzzer target (fuzz_*) nor a Go fuzz test (Fuzz*)'
                            % (e['where'], e['target']))

    # Every target runs in CI: CMake builds and run_fuzzers.ps1 runs every fuzz_<name>.c, so a target needs no line in a list
    if not cmake_takes_every_source(root):
        problems.append('%s/CMakeLists.txt: does not find the targets by file(GLOB ... fuzz_*.c), so CI would not build a new '
                        'target' % FUZZ_DIR)
    finds, listed = run_fuzzers_finds_targets(root)
    if listed:
        problems.append('%s/run_fuzzers.ps1: has a default list of -Targets, which a new target would have to be added to: it '
                        'finds every fuzz_<name>.c itself' % FUZZ_DIR)
    if not finds:
        problems.append("%s/run_fuzzers.ps1: does not find the targets by -Filter 'fuzz_*.c', so CI would not run a new one"
                        % FUZZ_DIR)
    for name in sorted(n[:-2] for n in os.listdir(os.path.join(root, FUZZ_DIR)) if re.match(r'^fuzz_\w+\.c$', n)):
        if name == 'fuzz_common':
            continue
        if max_len_of(os.path.join(root, FUZZ_DIR, name + '.c')) is None:
            problems.append('%s/%s.c: no line "// fuzz-max-len: <bytes>", the -max_len that %s/run_fuzzers.ps1 gives libFuzzer'
                            % (FUZZ_DIR, name, FUZZ_DIR))
        if not os.path.isdir(os.path.join(root, FUZZ_DIR, 'corpus', name)):
            problems.append('%s/%s.c: no seed corpus %s/corpus/%s' % (FUZZ_DIR, name, FUZZ_DIR, name))
        functions, malformed = reach_of(os.path.join(root, FUZZ_DIR, name + '.c'))
        for number in malformed:
            problems.append('%s/%s.c:%d: a line "// fuzz-reach:" that names no function, which run_fuzzers.ps1 refuses: '
                            'it is "// fuzz-reach: <function>"' % (FUZZ_DIR, name, number))
        for function in REACH.get(name, ()):
            if function not in functions:
                problems.append('%s/%s.c: no line "// fuzz-reach: %s", without which %s/run_fuzzers.ps1 no longer checks '
                                'that the seeds reach %s' % (FUZZ_DIR, name, function, FUZZ_DIR, function))
    for directory, target in sorted(set(go_fuzz) - named_go):
        problems.append('%s: %s is listed for no function in %s, so CI does not run it' % (directory, target, REGISTRY))

    return problems


def go_targets(root, module):
    entries, problems = parse_registry(os.path.join(root, REGISTRY))
    if problems:
        raise SystemExit('\n'.join(problems))
    pairs = []
    for e in entries:
        if not (e['target'] and e['target'].startswith('Fuzz')):
            continue
        if module == '.':
            package = './' + e['dir']
        elif e['dir'] == module:
            package = '.'
        elif e['dir'].startswith(module + '/'):
            package = './' + e['dir'][len(module) + 1:]
        else:
            continue
        pair = (package, e['target'])
        if pair not in pairs:
            pairs.append(pair)
    return pairs


def main():
    ap = argparse.ArgumentParser(description='The fuzz target gate of ADR-0040 item 1')
    ap.add_argument('mode', nargs='?', default='check', choices=['check', 'go-targets'])
    ap.add_argument('module', nargs='?', help='go-targets: the directory of the Go module, "." for the repository root')
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    args = ap.parse_args()

    if args.mode == 'go-targets':
        if args.module != '.' and args.module not in GO_SCOPE:
            ap.error('go-targets needs "." or one of: ' + ', '.join(GO_SCOPE))
        for package, target in go_targets(args.root, args.module):
            print(package, target)
        return 0

    problems = check(args.root)
    for p in problems:
        print('::error::' + p if os.environ.get('GITHUB_ACTIONS') else p)
    if problems:
        print('%d problems: a parser or wire-format handler needs a fuzz target that runs in CI (ADR-0040)' % len(problems))
        return 1
    print('Every parser and wire-format handler of the new core has a fuzz target that runs in CI (%s)' % REGISTRY)
    return 0


if __name__ == '__main__':
    sys.exit(main())
