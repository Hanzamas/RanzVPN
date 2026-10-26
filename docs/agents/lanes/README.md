# The lane script

[lanes-template.js](lanes-template.js) is the Workflow script that launches lanes. One lane is one agent in its own git worktree. It builds one ticket, or continues one pull request, and returns one result. The integrator ([integrator.md](../integrator.md)) runs the script. The commands in its rules are `gh api` commands, so the same script runs on the laptop and in a cloud session ([integrator-cloud.md](../integrator-cloud.md)).

## Run it

1. **Copy** the file out of the repository: to the scratchpad of the session, or to `/tmp`. Name it for the run, for example `lanes-2026-10-26-a.js`, and change `meta.name`. A filled copy is never committed.
2. **Fill `QUOTE`.** The words of the maintainer that start this run, verbatim, with their date. In a cloud run they are the words that he wrote into the routine. A lane that sees no authority line refuses to commit, push or open a pull request. Never write words that he did not write. The script stops, when a lane is active, if `QUOTE` or `STATE` still says `FILL IN`.
3. **Fill `STATE`.** The facts of the moment: the date, the pull requests that merged, the pull requests and tickets that other lanes work on. Replace the old text for every run. Never stack a second `STATE`: the lane would read two states that disagree.
4. **Fill `LANES`.** Copy `EXAMPLE_LANE` into the array, once per lane. Keep a finished lane in the array with `skip: true`, so that a new run shows what was done.
5. **Run** it with the Workflow tool, with the path of your copy as `scriptPath`. A Workflow runs at most `CPUs - 2` lanes at once, which is 2 in a cloud container, and it queues the others. So run the lanes in batches of at most 2, each batch its own Workflow (its own copy, with `skip: true` on the lanes of the other batches), and the batches run side by side. Before you run one, check that no running Workflow, and no tick comment of the last 3 hours, has the same lane. After a cut-off, start a new run with resume lanes. Do not use `resumeFromRunId` for that: a new `STATE` changes every prompt, so nothing would come from the cache, and in the cloud the journal of the old run is gone.

## A lane object

| Field | Meaning |
|---|---|
| `key` | A short name, used for the label and the result. Unique in the run. |
| `model` | `opus` for the C data path, crypto, drivers and hard design. `sonnet` for Go, UI, CLI, docs and CI (the script sets effort `max`). Always set. The script refuses any other value. |
| `skip` | `true` leaves the lane out. |
| `task` | What the lane does. |

## Write a task

A new lane names the ticket, the branch, what to read first, the shape of the pull request and what is close to its files. `EXAMPLE_LANE` is the pattern. Name the ADRs and the code that the ticket touches, and say which other lanes change the same files at the same time.

A resume lane continues what an earlier lane left. It names the pull request, the branch and the head, says what failed, and gives the commands:

```
YOUR LANE (resume): ticket #NNN (KEY-N: title), PR NNN, branch `area/NNN-short-name`, head abcd1234.
The earlier lane was cut off. Run `git fetch origin`, then
`git switch -c resume-<key>-<n> origin/area/NNN-short-name`, merge origin/integration, read the
failed jobs of the head, fix forward, and push with `git push origin HEAD:area/NNN-short-name`
after every commit. Check every acceptance criterion of #NNN and report the ones not met.
Do not open another pull request.
```

The local branch has its own name, so that it does not clash with a branch that another worktree has checked out. A branch that has no pull request yet says so, and the lane opens one. A batch lane names several branches and says: merge them one at a time into the first one, resolve the overlaps, keep the merge commits, and open no other pull request.

## Read the result

Each lane returns `ok`, `pr`, `head`, `ci`, `met`, `notMet`, `newTerms` and `blocked`.

- `ok: false` means not done. Never queue its pull request for merge. The integrator reads the pull request itself before it merges.
- `blocked` is a command that the permission check refused. The integrator reports it under `blocked:` with its text. Never retry it.
- `newTerms` go into the report. A lane never edits `CONTEXT.md`. The integrator collects the new terms and writes them in a docs pull request.

## Rules of the file

- Every string is plain: single quotes and no apostrophes, so that no quote ends a string early.
- No `Date.now()` and no `Math.random()`. The Workflow tool refuses them, because they break a resume.
- The rules of the lane are the `RULES` array. When a rule changes, change it there and in the page that it mirrors.
- The pace rule is about 5 lanes at once. The script warns above 6.
