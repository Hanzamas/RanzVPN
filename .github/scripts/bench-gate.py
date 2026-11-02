# The performance regression gate of ADR-0040 item 5: each benchmark case is compared with its
# recorded median, and a case slower than that median by more than its margin fails the job.
#
# Results are the "BENCH <case> <value> <unit>" lines of the harness (vpntest bench and the other
# vpntest tests that print BENCH lines, .github/scripts/vpntest.ps1 saves them to
# build/harness-out/bench-<arch>.txt, and with RANZ_BENCH_RUNS=3 the second and third run to
# bench-<arch>-run2.txt and bench-<arch>-run3.txt). A case is a rate when its unit is one of RATE_UNITS
# (higher is faster) and a time when it is one of TIME_UNITS (lower is faster); other lines (sizes,
# counts, the "<case>_runs" lists) are not compared. How much slower a case is: median / value - 1 for a
# rate, value / median - 1 for a time.
#
# Noise on a shared runner makes one run an unreliable witness of a regression, so the gate judges the
# best of the runs that it is given: the minimum of a time, the maximum of a rate, of each case over the
# result files. A slowdown that every run shows is real; one that a run shows is noise. Two rules for
# what remains:
# - a time case whose recorded median is under SMALL_US microseconds (ip_table_expire_1024 takes 2 to 5)
#   is too short for a relative margin: a scheduler tick is more than the margin. It fails only when it is
#   slower than its median by more than SMALL_SLACK_US microseconds;
# - every other case fails when it is slower than its median by more than its margin.
#
# What the best is the best of matters. A case that a run measures once has one sample, however many result files there are
# (the enrolment of the scale scenario was measured once in a run, and its three files held that one number three times), and a
# run that is slow in that one sample is slow for the gate. So the gate counts, for each case, the result files that hold it,
# which are the samples that it judges the best of, and prints the count in its table. --min-samples PATTERN N WHAT fails the run
# when a recorded case that matches PATTERN (a shell wildcard) has fewer than N: a run that measures its enrolments once, and not
# the three that it should, fails and is not judged on the one.
#
# The recorded medians, one file per architecture (.github/quality/bench-<arch>.txt):
#   <case> <median> <unit> <margin %>
# record makes the file from the result files of several CI runs: the median of each case over the
# runs, and a margin of twice the slowest run's distance from that median, rounded up to 5 %, and at
# least --min-margin. A time that every run printed in whole units (2 us) also gets a margin of at
# least two such units. A case whose median is 0 is left out: no margin is relative to 0. Every result file
# is a run of its own, unless --per-run says that a RESULTS argument names the files of one run: that run
# is then the best of them, the number that compare judges, so the margin is the spread of what the gate
# judges between runs and not the spread of its samples.
#
# Usage:
#   python bench-gate.py compare --medians FILE [--runs N] [--min-samples PATTERN N WHAT]... RESULTS...
#                                                            exit 1 when a recorded case is slower
#                                                            than it may be, or missing, or fewer than
#                                                            N result files are given, or a case has
#                                                            fewer samples than --min-samples asks for
#   python bench-gate.py record --out FILE [--min-margin 25] [--per-run] [--note TEXT] RESULTS...
# A RESULTS argument with a wildcard (bench-x64*.txt) names every file that matches it.
#
# Standard library only.

import argparse
import fnmatch
import glob
import math
import os
import re
import statistics
import sys

RATE_UNITS = {'frames/s', 'Mbit/s', 'ops/s'}
TIME_UNITS = {'ns', 'us', 'ms', 's'}
# A time unit in microseconds
TIME_IN_US = {'ns': 0.001, 'us': 1.0, 'ms': 1000.0, 's': 1000000.0}
# A time case under SMALL_US microseconds fails only above SMALL_SLACK_US microseconds over its median
SMALL_US = 50
SMALL_SLACK_US = 100

_BENCH_RE = re.compile(r'^BENCH (\S+) (-?[0-9]+(?:\.[0-9]+)?) (\S+)\s*$')


def expand(paths):
    # The result files that the arguments name; a wildcard names every file that matches it
    out, problems = [], []
    for path in paths:
        if any(c in path for c in '*?['):
            found = sorted(glob.glob(path))
            if not found:
                problems.append('no result file matches %s' % path)
            out.extend(found)
        else:
            out.append(path)
    return out, problems


def read_results(path):
    # case -> (value, unit) of one result file
    out = {}
    with open(path, encoding='utf-8-sig', errors='replace') as f:
        for line in f:
            m = _BENCH_RE.match(line.strip())
            if not m or m.group(1).endswith('_runs'):
                continue
            unit = m.group(3)
            if unit in RATE_UNITS or unit in TIME_UNITS:
                out[m.group(1)] = (float(m.group(2)), unit)
    return out


def best_results(paths):
    # case -> (best value, unit) over the result files: the minimum of a time, the maximum of a rate; and case -> the number of
    # result files that hold it, the samples that the best is the best of
    best, samples, problems = {}, {}, []
    for path in paths:
        for case, (value, unit) in read_results(path).items():
            samples[case] = samples.get(case, 0) + 1
            if case not in best:
                best[case] = (value, unit)
            elif best[case][1] != unit:
                problems.append('%s: the unit is %s in %s and %s in an earlier run' % (case, unit, path, best[case][1]))
            elif unit in RATE_UNITS:
                best[case] = (max(best[case][0], value), unit)
            else:
                best[case] = (min(best[case][0], value), unit)
    return best, samples, problems


def slowdown(median, value, unit):
    # How much slower value is than median, as a fraction (0.3 is 30 % slower; negative is faster)
    if unit in RATE_UNITS:
        return math.inf if value <= 0 else median / value - 1
    return value / median - 1


def read_medians(path):
    medians, problems = {}, []
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            fields = line.split('#', 1)[0].split()
            if not fields:
                continue
            try:
                if len(fields) != 4:
                    raise ValueError
                median, margin = float(fields[1]), float(fields[3])
                if median <= 0 or margin < 0 or (fields[2] not in RATE_UNITS and fields[2] not in TIME_UNITS):
                    raise ValueError
                medians[fields[0]] = (median, fields[2], margin)
            except ValueError:
                problems.append('%s:%d: "%s" is not "<case> <median> <unit> <margin %%>" with a median above 0 and a '
                                'rate or time unit' % (path, number, line.strip()))
    return medians, problems


def compare(args):
    medians, problems = read_medians(args.medians)
    paths, more = expand(args.results)
    problems += more
    if len(paths) < args.runs:
        problems.append('%d result files given, and the gate judges the best of %d runs' % (len(paths), args.runs))
    results, samples, more = best_results(paths)
    problems += more

    lines = ['| case | median | best | samples | slower by | margin | |', '|---|---:|---:|---:|---:|---:|---|']
    for case in sorted(medians):
        median, unit, margin = medians[case]
        if case not in results:
            problems.append('%s: recorded in %s and not in this run\'s results' % (case, args.medians))
            lines.append('| %s | %g %s | - | 0 | - | %g%% | missing |' % (case, median, unit, margin))
            continue
        value, got_unit = results[case]
        if got_unit != unit:
            problems.append('%s: the unit is %s in this run and %s in %s' % (case, got_unit, unit, args.medians))
            continue
        slower = slowdown(median, value, unit)
        verdict = 'ok'
        if unit in TIME_UNITS and median * TIME_IN_US[unit] < SMALL_US:
            # Too short for a relative margin: only a slowdown of SMALL_SLACK_US microseconds counts
            extra_us = (value - median) * TIME_IN_US[unit]
            if extra_us > SMALL_SLACK_US:
                verdict = 'too slow'
                problems.append('%s: %g %s, %g us slower than the recorded median %g %s, which is under %g us and may be '
                                'slower by %g us' % (case, value, unit, round(extra_us, 1), median, unit, SMALL_US, SMALL_SLACK_US))
            elif slower * 100 > margin:
                verdict = 'ok, under %g us' % SMALL_US
        elif slower * 100 > margin:
            verdict = 'too slow'
            problems.append('%s: %g %s, %.1f%% slower than the recorded median %g %s; the margin is %g%%'
                            % (case, value, unit, slower * 100, median, unit, margin))
        lines.append('| %s | %g %s | %g %s | %d | %.1f%% | %g%% | %s |' % (case, median, unit, value, unit, samples[case], slower * 100, margin, verdict))
    new = sorted(set(results) - set(medians))

    # What each case is judged on: the samples that --min-samples asks for, and how many the result files hold
    counted = []
    for pattern, wanted, what in args.min_samples:
        matching = [case for case in sorted(medians) if fnmatch.fnmatchcase(case, pattern)]
        if not matching:
            problems.append('--min-samples %s %d %s: no case recorded in %s matches it' % (pattern, wanted, what, args.medians))
            continue
        held = [samples[case] for case in matching if case in results]
        for case in matching:
            if case in results and samples[case] < wanted:
                problems.append('%s: the result files hold %d of the %d %s that the gate is asked to judge the best of (--min-samples %s %d %s)'
                                % (case, samples[case], wanted, what, pattern, wanted, what))
        if held:
            counted.append('%s: %d %s, each judged on the best of %s %s (at least %d asked for)'
                           % (pattern, len(matching), 'case' if len(matching) == 1 else 'cases',
                              held[0] if min(held) == max(held) else '%d to %d' % (min(held), max(held)), what, wanted))

    print('\n'.join(lines))
    for line in counted:
        print(line)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write('### Performance regression gate (%s, best of %d runs)\n\n%s\n\n%s'
                    % (os.path.basename(args.medians), len(paths), '\n'.join(lines), ''.join(line + '\n\n' for line in counted)))
    if new:
        print('Not compared, no recorded median (record one with bench-gate.py record): ' + ', '.join(new))
    for p in problems:
        print('::error::' + p if os.environ.get('GITHUB_ACTIONS') else p)
    if problems:
        print('%d problems: a benchmark slower than its recorded median by more than its margin fails the build '
              '(ADR-0040 item 5)' % len(problems))
        return 1
    print('%d benchmark cases within their margin of the recorded median (best of %d runs)' % (len(medians), len(paths)))
    return 0


def record(args):
    # The runs: every result file, or with --per-run the files that one RESULTS argument names, as the best of them
    groups, problems = [], []
    for arg in args.results:
        paths, more = expand([arg])
        problems += more
        if args.per_run:
            groups.append(paths)
        else:
            groups.extend([path] for path in paths)
    runs = []
    for group in groups:
        best, _, more = best_results(group)
        problems += more
        runs.append(best)
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        return 1
    cases = {}
    for run in runs:
        for case, (value, unit) in run.items():
            cases.setdefault(case, []).append((value, unit))

    out = ['# The recorded medians of the performance regression gate (ADR-0040 item 5,',
           '# .github/scripts/bench-gate.py): <case> <median> <unit> <margin %>.',
           '# Recorded by bench-gate.py record from %d CI runs%s the margin twice the slowest run\'s distance'
           % (len(runs), ', each the best of its result files as compare judges them,' if args.per_run else ','),
           '# from the median, rounded up to 5 %%, at least %g %% and at least two units of a time printed' % args.min_margin,
           '# in whole units.']
    if args.note:
        out += ['# ' + line for line in args.note.splitlines()]
    for case in sorted(cases):
        units = {u for _, u in cases[case]}
        if len(units) != 1:
            print('%s: more than one unit (%s), left out' % (case, ', '.join(sorted(units))), file=sys.stderr)
            continue
        unit = units.pop()
        values = [v for v, _ in cases[case]]
        median = statistics.median(values)
        if median <= 0:
            print('%s: median %g, left out' % (case, median), file=sys.stderr)
            continue
        worst = max(slowdown(median, v, unit) for v in values) * 100
        margin = max(args.min_margin, math.ceil(2 * worst / 5) * 5)
        if unit in TIME_UNITS and all(v == int(v) for v in values):
            # A time printed in whole units moves in steps of one: two steps are no regression
            margin = max(margin, math.ceil(200 / median / 5) * 5)
        out.append('%s %g %s %g' % (case, median, unit, margin))
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(out) + '\n')
    return 0


def main():
    ap = argparse.ArgumentParser(description='The performance regression gate of ADR-0040 item 5')
    sub = ap.add_subparsers(dest='mode', required=True)
    p = sub.add_parser('compare')
    p.add_argument('--medians', required=True)
    p.add_argument('--runs', type=int, default=1, help='the number of result files that must be given: the runs of which '
                   'the gate judges the best')
    p.add_argument('--min-samples', nargs=3, action='append', default=[], metavar=('PATTERN', 'N', 'WHAT'),
                   help='the recorded cases that match PATTERN (a shell wildcard) must each be in at least N result files, '
                   'the N WHAT (enrolments, say) that the gate judges the best of')
    p.add_argument('results', nargs='+')
    p = sub.add_parser('record')
    p.add_argument('--out', required=True)
    p.add_argument('--min-margin', type=float, default=25)
    p.add_argument('--per-run', action='store_true', help='a RESULTS argument names the result files of one CI run, which '
                   'counts as the best of them, as compare judges it; without it every result file is a run')
    p.add_argument('--note', default='')
    p.add_argument('results', nargs='+')
    args = ap.parse_args()
    if args.mode == 'compare':
        rules = []
        for pattern, wanted, what in args.min_samples:
            if not wanted.isdigit() or int(wanted) < 1:
                ap.error('--min-samples %s %s %s: N is not a whole number from 1' % (pattern, wanted, what))
            rules.append((pattern, int(wanted), what))
        args.min_samples = rules
    return compare(args) if args.mode == 'compare' else record(args)


if __name__ == '__main__':
    sys.exit(main())
