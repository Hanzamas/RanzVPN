# The job timeout check of CI-INTEG-1-R1 (#597): every job of every workflow in .github/workflows has timeout-minutes, or calls a
# reusable workflow with uses: (GitHub takes no timeout-minutes on such a job, and the jobs of the workflow that it calls have
# their own, which this check reads like those of any workflow). Since CI-INTEG-1 (#585) a push to integration or master no longer
# cancels the run of the push before it, so a job that hangs holds the group of its workflow until it ends, and a job with no
# timeout-minutes can hold it for 360 minutes, the limit that GitHub gives it.
#
# The timeout of a job is the key timeout-minutes of the job itself. The one of a step bounds that step alone, so it does not count.
# A number must be above 0 and below 360, the limit of a job with no timeout-minutes; an expression is taken as it stands (fuzz.yml
# takes the limit of its legs from its plan).
#
# It reads a workflow by its lines, as formal.py and ci-plan.py read theirs. The jobs are the keys one level under the line "jobs:",
# and a key of a job is a line at the indentation of the first line under the job's name, so a timeout-minutes or a uses: in a step
# (an item that starts with "- ") or in the text of a script is not the job's. A job or a workflow that it cannot read (a job written as
# a flow mapping, a workflow with no jobs, no workflow at all) fails: a check that reads nothing passes everything.
#
# Usage: python job-timeout-check.py [--root DIR]    exit status 1 when a job has no timeout
#
# Standard library only.

import argparse
import os
import re
import sys

WORKFLOWS = '.github/workflows'
# The limit that GitHub gives a job with no timeout-minutes
DEFAULT_MINUTES = 360

JOBS = re.compile(r'^jobs:\s*(?:#.*)?$')
KEY = re.compile(r'^([A-Za-z0-9_-]+):(?:\s+(.*))?$')


def value_of(text):
    # What follows the colon of a key, without a comment
    return re.sub(r'(?:^|\s)#.*$', '', text or '').strip()


def read_jobs(lines):
    """The jobs of a workflow as {name, line, indent, keys}, with the keys of each job as {key: (line, value)}, and the (line, text)
    of what could not be read."""
    start = next((i for i, line in enumerate(lines) if JOBS.match(line)), None)
    if start is None:
        return [], [(1, 'has no line "jobs:"')]
    jobs = []
    unread = []
    job_indent = None
    job = None
    for number, line in enumerate(lines[start + 1:], start + 2):
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        indent = len(line) - len(line.lstrip(' '))
        if indent == 0:
            break
        if job_indent is None:
            job_indent = indent
        key = KEY.match(text)
        if indent < job_indent:
            unread.append((number, "'%s' is indented less than the first job" % text))
        elif indent == job_indent:
            if key is None or value_of(key.group(2)):
                unread.append((number, "'%s' is not a job: the check reads a job as its name, a colon, and its keys on the lines below" % text))
                job = None
            else:
                job = {'name': key.group(1), 'line': number, 'indent': None, 'keys': {}}
                jobs.append(job)
        elif job is not None:
            if job['indent'] is None:
                job['indent'] = indent
            if indent == job['indent'] and key is not None:
                job['keys'].setdefault(key.group(1), (number, value_of(key.group(2))))
    if not jobs and not unread:
        unread.append((start + 1, 'has no job under "jobs:"'))
    return jobs, unread


def bad_timeout(value):
    """Why the value of timeout-minutes is no bound, or None when it is one."""
    value = value.strip('\'"')
    if value.startswith('${{') and value.endswith('}}'):
        return None
    if not value:
        return 'has timeout-minutes with no value'
    if not re.fullmatch(r'\d+(?:\.\d+)?', value):
        return 'has timeout-minutes: %s, which is no number of minutes' % value
    if float(value) <= 0:
        return 'has timeout-minutes: %s, which is no time at all' % value
    if float(value) >= DEFAULT_MINUTES:
        return ('has timeout-minutes: %s, which is not below the %d minutes that GitHub gives a job with no timeout-minutes'
                % (value, DEFAULT_MINUTES))
    return None


def check(root):
    """The problems as (workflow, line, message), and the number of workflows, of jobs with a timeout and of jobs that call a workflow."""
    folder = os.path.join(root, *WORKFLOWS.split('/'))
    names = sorted(n for n in os.listdir(folder) if n.endswith(('.yml', '.yaml'))) if os.path.isdir(folder) else []
    problems = []
    bounded = 0
    reusable = 0
    if not names:
        problems.append((WORKFLOWS, 1, 'holds no workflow: the check has nothing to read'))
    for name in names:
        shown = '%s/%s' % (WORKFLOWS, name)
        with open(os.path.join(folder, name), encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
        jobs, unread = read_jobs(lines)
        problems += [(shown, number, 'the check cannot read it: %s' % what) for number, what in unread]
        for job in jobs:
            uses = job['keys'].get('uses')
            if uses and uses[1]:
                reusable += 1
                continue
            found = job['keys'].get('timeout-minutes')
            if found is None:
                problems.append((shown, job['line'], 'the job %s has no timeout-minutes: GitHub ends it only after %d minutes, and the '
                                 'run of the next push to its group waits that long (CI-INTEG-1-R1, #597)' % (job['name'], DEFAULT_MINUTES)))
                continue
            why = bad_timeout(found[1])
            if why:
                problems.append((shown, found[0], 'the job %s %s' % (job['name'], why)))
            else:
                bounded += 1
    return problems, len(names), bounded, reusable


def plural(count, word):
    return '%d %s%s' % (count, word, '' if count == 1 else 's')


def main():
    ap = argparse.ArgumentParser(description='The job timeout check of CI-INTEG-1-R1')
    ap.add_argument('--root', default=os.environ.get('GITHUB_WORKSPACE') or os.getcwd())
    args = ap.parse_args()
    problems, workflows, bounded, reusable = check(os.path.abspath(args.root))
    for path, line, message in problems:
        if os.environ.get('GITHUB_ACTIONS'):
            print('::error file=%s,line=%d::%s' % (path, line, message))
        else:
            print('%s:%d: %s' % (path, line, message))
    if problems:
        print('%s: every job of a workflow has timeout-minutes, or calls a reusable workflow' % plural(len(problems), 'problem'))
        return 1
    print('Every job of the %s in %s has a timeout: %d with timeout-minutes, %d that call a reusable workflow'
          % (plural(workflows, 'workflow'), WORKFLOWS, bounded, reusable))
    return 0


if __name__ == '__main__':
    sys.exit(main())
