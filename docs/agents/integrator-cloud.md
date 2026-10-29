# The integrator in a cloud session

This page is for an integrator that runs in a cloud session, started by a routine, so that the job goes on when the maintainer's PC is off. Read [integrator.md](integrator.md) first. It has the rules. This page has what is different in the cloud: the limits, the commands and the shape of a tick.

## What a cloud session has and lacks

The check of 2026-10-26 showed this.

**It works:**

- `git push origin HEAD:<branch>`, also for a commit that edits a file of `.github/workflows`.
- The tools of the github MCP server. The check read the open pull requests, the 60 check runs of the head of a pull request, a commit, and the log of a failed job.
- `gh api` for REST reads, and `gh run list`, `gh run watch`, `gh run view --log-failed`.
- The tools Workflow, Agent with `isolation: worktree`, and Monitor.

**It does not work:**

- GraphQL. So `gh pr create`, `gh pr list`, `gh pr checks`, `gh pr view`, `gh pr merge` and `gh issue list` fail. The check saw them fail. The other `gh pr` and `gh issue` commands (`edit`, `ready`, `comment`, `close`, `view`) use GraphQL too: treat them the same. Use the commands of this page. The proxy answers a GraphQL call with a message that names the REST routes to use in its place, among them the CCR route that marks a draft ready (see "Mark a draft ready").
- `gh auth status`. It prints `The token in GH_TOKEN is invalid`, and `gh api` REST calls work all the same, because the proxy adds the credential (seen on 2026-10-29). Do not stop at that line: test with `gh api repos/Hanzamas/RanzVPN/issues/<heartbeat>`.
- A tool for the usage of the plan. There is no `get_usage`. Only the limit of the plan stops a session.
- `gh api --paginate` on a list of more than 100 rows. GitHub answers with a `Link` url of the form `repositories/<id>/...`, and the proxy refuses it (403, "Numeric-ID repository paths are not supported"). Read each page yourself with `per_page=100&page=N` and stop at a page of fewer than 100 rows (seen on 2026-10-27, on the list of the ready tickets, which has more than 100 rows).
- The search API. `gh api search/issues` answers 403 ("sessions are bound to their configured repositories"). So the progress count at the end of "Other reads" and the search for the heartbeat issue fail: the routine prompt names the heartbeat issue, and the progress is counted from the lists of issues. The tool `search_issues` of the github MCP server is a search by meaning, not a count.

**The limits:**

- A foreground command ends after 10 minutes. Monitor ends after 30 minutes for each arm. Never wait with a foreground sleep.
- The container is reclaimed when it is idle. What is not pushed is lost.
- The clone is shallow, at `/home/user/RanzVPN`. It is on the default branch, unless the environment says another.
- Only HTTPS on port 443 goes out.
- `CronCreate` lives as long as the session. The routine is the only schedule that survives.

**The routine tried the writes** on 2026-10-26: comments, edits of comments, closing tickets, pull requests of lanes, reruns and the REST merge all worked, after the permission check had refused the REST merge of one pull request twice ("Merge Without Review"). If a write fails, the tick stops that action, puts the error in its report and goes on with the work that does not need it.

## What clears the permission check

A routine runs in auto mode. A classifier blocks some actions, among them "merging a pull request that no human approved". The saved prompt of a routine is not live user input, and the documentation says that it cannot act as approval or consent. So a paragraph of the prompt, such as EXPLICIT PERMISSION, does not clear the check. It only tells the tick what the maintainer allows. Three things clear it. The first two were in place on 2026-10-26, when the cloud merged a pull request by itself (#426, 04:09Z). The third is the one to add if a refusal comes back.

1. **Narrow allow rules** in the allowed tools of the routine: `Bash(gh api -X PUT *pulls/*/merge*)`, `Bash(gh api --method PUT *pulls/*/merge*)` and `mcp__github__merge_pull_request` for the merge, and, because the classifier refused to comment on and close tickets again and again from 2026-10-26 ("External System Writes"), `Bash(gh api --method POST repos/Hanzamas/RanzVPN/issues*)`, `Bash(gh api --method PATCH repos/Hanzamas/RanzVPN/issues*)`, the `-X` forms of both, and the same four for `pulls`. A command that such a rule matches never reaches the classifier. A broad rule, such as a plain `Bash`, is dropped in auto mode. A rule matches the text of one command, so the merge command of this page stays one simple command with literal values. A leading assignment of a variable, or a command inside `$(...)`, defeats the rule.
2. **`autoMode.allow` in the server-managed settings of the organization.** They are at claude.ai, Organization settings, Claude Code, Managed settings, and only an Owner can edit them. The maintainer set a rule there that allows merges into `integration` of this repository, and never into `master`. A cloud session receives these settings when it starts.
3. **`permissions.allow` in `.claude/settings.json` of the repository.** A cloud session with one repository reads it. The classifier does not read `autoMode` from the repository, but it honours permission rules. Add the rules of layer 1 there if the first two are not enough. This file widens what an agent may do, so a change of it goes in its own pull request, and the report names it.

## The shape of the job

The job is a long-running session that a routine starts. The routine fires every hour (a routine cannot fire more often), and the maintainer may keep two more routines at other minutes, so that a dead session is replaced within 20 minutes. A session that finds another one alive stands down at once. The session that wins the heartbeat stays alive: it keeps the lanes full, waits with Monitor (30 minutes for each arm, then it arms again), reacts to every event within a minute, and refreshes its heartbeat comment every 20 minutes. It ends only when the plan limit stops it, or at the end of the work. Nothing that matters lives in the container: the state is in the pull requests, the branches, the tickets and the heartbeat issue, so a session that dies is replaced by the next one, which reads GitHub and continues. The `lanes` line of the report is what the next session reads to know which lanes run.

## The commands

All commands are bash. The repository is `Hanzamas/RanzVPN`. `<n>` is a number and `<sha>` is a full commit sha. `gh api` prints JSON and `--jq` filters it. A call with `-f` or `-F` is a POST unless you give `--method`. Put a long text in a file and send it with `-F body=@<file>`. Shell variables do not survive between commands in a session, so write what you need later (a run id, a comment id) into a file outside the repository.

Where the github MCP server has a tool for the action, it is named. The names are the ones seen in the check. If a tool is missing in your session, use the `gh api` command of the same action.

### The open pull requests into integration

```
gh api "repos/Hanzamas/RanzVPN/pulls?state=open&base=integration&per_page=100" --jq '.[] | [.number, .draft, .head.sha, .head.ref, .title] | @tsv'
```

Tool: `list_pull_requests`. This list has no `mergeable` fields. Read them with the next command.

### One pull request

```
gh api repos/Hanzamas/RanzVPN/pulls/<n> --jq '[.number, .draft, .mergeable, .mergeable_state, .head.sha, .head.repo.full_name, .base.ref] | @tsv'
gh api repos/Hanzamas/RanzVPN/pulls/<n> --jq '[.labels[].name] | join(",")'
gh api repos/Hanzamas/RanzVPN/pulls/<n> --jq .body
```

Tool: `pull_request_read`. `mergeable_state` is `clean` (can merge), `unstable` (a check fails or runs), `dirty` (conflict), `blocked`, `behind`, `draft` or `unknown`. GitHub works out `mergeable` in the background. `null` or `unknown` means: ask again in a few seconds.

### The CI runs of a head

One row for the newest run of each workflow. Older runs that a newer run replaced do not show:

```
gh api "repos/Hanzamas/RanzVPN/actions/runs?head_sha=<sha>&per_page=100" --jq '[.workflow_runs | group_by(.path)[] | max_by(.id)] | .[] | [.id, .path, .status, .conclusion] | @tsv'
```

Read it so: a row whose status is not `completed` is not finished (it runs, it is queued, or it is `pending` behind an older run of the same workflow). A completed row whose conclusion is not `success` (or `skipped`) failed. The head is green when there are at least 3 rows and all of them are `completed` and `success`. This is rule 4 of the merge procedure.

Why not the check runs: a new label or a new push starts new runs. They cancel or replace the old ones. The old check runs stay in the list, often as `cancelled`, so a list of check runs shows failures that are not failures. Matrix jobs that were cancelled before they expanded even keep a name like `install (${{ matrix.platform.ARCHITECTURE }})`. To find one job by its name, take the newest check run of that name (the highest id).

### The jobs of a run

```
gh api "repos/Hanzamas/RanzVPN/actions/runs/<run-id>/jobs?per_page=100" --jq '.jobs[] | [.id, .name, .status, .conclusion] | @tsv'
```

For rule 5 of the merge procedure, read the jobs of the newest `windows.yml` run. The id of a job is also the id of its check run.

### The check runs of a head

```
gh api "repos/Hanzamas/RanzVPN/commits/<sha>/check-runs?per_page=100" --jq '.check_runs[] | [.id, .name, .status, .conclusion] | @tsv'
```

Tool: `pull_request_read` with the method `get_check_runs`. One row for each job of each run, with the older and cancelled ones too (see above). Use it to find the id of a failed job. If the head has more than 100 check runs, add `--paginate`.

### The log of a failed job

```
gh run view --repo Hanzamas/RanzVPN --job <job-id> --log-failed
gh api --allow-escape-sequences repos/Hanzamas/RanzVPN/actions/jobs/<job-id>/logs
```

The first works once the run has finished. The second works while it still runs. Tool: `get_job_logs`. The run id of a job: `gh api repos/Hanzamas/RanzVPN/actions/jobs/<job-id> --jq .run_id`.

### Watch a run, rerun a failed job

```
gh run list --repo Hanzamas/RanzVPN --commit <sha>
gh run watch <run-id> --repo Hanzamas/RanzVPN --interval 60 --compact
gh run rerun <run-id> --repo Hanzamas/RanzVPN --failed
```

Start `gh run watch` as a background command or with Monitor, never in the foreground: it ends only when the run ends. Rerun only the run of the live head, and only for a known flake.

### Create a pull request

```
gh api --method POST repos/Hanzamas/RanzVPN/pulls -f title="<title>" -f head=<branch> -f base=integration -F body=@<file> -F draft=true --jq '[.number, .html_url] | @tsv'
```

Leave out `-F draft=true` for a pull request that is ready. Tool: `create_pull_request`. The answer 422 means that a pull request for the branch already exists, or that the branch has no commit that `integration` lacks.

### Add a label

```
gh api --method POST repos/Hanzamas/RanzVPN/issues/<n>/labels -f "labels[]=full-ci"
```

A pull request is an issue for labels and comments, so `<n>` is the number of the pull request.

### Mark a draft ready

REST has no call for it, and `gh pr ready` uses GraphQL, which the proxy refuses. The proxy has its own route. It worked on 2026-10-29 (PR 484), and answered `{"draft":false}`:

```
gh api --method POST repos/Hanzamas/RanzVPN/pulls/<n>/ccr/ready_for_review
```

`POST .../pulls/<n>/ccr/convert_to_draft` goes the other way. Mark a draft ready only when its lane says that the work is done, then take the pull request through the merge procedure like any other.

### Merge a pull request

```
gh api --method PUT repos/Hanzamas/RanzVPN/pulls/<n>/merge -f merge_method=merge -f sha=<head-sha> --jq '[.merged, .sha] | @tsv'
```

`sha` must be the head that you checked at your second look. If the head moved, GitHub answers 409 (`Head branch was modified`) and merges nothing. That is the point of the parameter. A 405 means that the pull request is not mergeable now. After either answer, read the pull request again and start at the first look. Do not retry the same call.

Copy the sha from the verdict of your look, character for character. A sha with one wrong character gets the same 409 as a real push (seen on 2026-10-29: the head had not moved, the sha was mistyped). So on a 409, read the head again and compare it with what you passed before you look for a lane that pushed.

The tool `merge_pull_request` of the github MCP server has a parameter `expectedHeadSha` in its schema (seen on 2026-10-29, not tried). Prefer the command. If you must use the tool, read the head again right before the call.

### Read a ticket

```
gh api repos/Hanzamas/RanzVPN/issues/<n> --jq '[.number, .state, ([.labels[].name] | join(",")), .title] | @tsv'
gh api repos/Hanzamas/RanzVPN/issues/<n> --jq .body
gh api "repos/Hanzamas/RanzVPN/issues/<n>/comments?per_page=100" --jq '.[].body'
```

### The ready tickets

```
for p in 1 2 3; do gh api "repos/Hanzamas/RanzVPN/issues?state=open&labels=ready-for-agent&per_page=100&page=$p" --jq '.[] | select(.pull_request == null) | select([.labels[].name] | any(. == "postponed" or . == "needs-triage" or . == "parked") | not) | [.number, .title] | @tsv'; done
```

The loop reads three pages, which holds 300 rows (there were 108 on 2026-10-27). The proxy does not take `--paginate` (see "What a cloud session has and lacks"). This list also holds specs. A ticket has a line `Ticket key:` in its body. For each candidate, read its body, find the numbers in its `## Blocked by` section, and read the state of each blocker (`gh api repos/Hanzamas/RanzVPN/issues/<m> --jq .state`). The ticket is ready when every blocker is `closed`. See "Launching lanes" in [integrator.md](integrator.md).

### Comment, edit a comment, close a ticket

```
gh api --method POST repos/Hanzamas/RanzVPN/issues/<n>/comments -F body=@<file> --jq .id
gh api --method PATCH repos/Hanzamas/RanzVPN/issues/comments/<comment-id> -F body=@<file>
gh api --method PATCH repos/Hanzamas/RanzVPN/issues/<n> -f state=closed -f state_reason=completed
```

Close a ticket in two calls: the comment first (the fixed text of the merge procedure), then the close. The tools for issues have other names in other versions of the server, so look at the tool list.

### Other reads

```
gh api repos/Hanzamas/RanzVPN/branches/<branch> --jq .commit.commit.committer.date
gh run list --repo Hanzamas/RanzVPN --branch integration --event push --limit 8
git ls-remote --heads origin
```

The first gives the date of the newest commit of a branch. A branch with a commit in the last 45 minutes is busy. The second shows the newest full runs on `integration`: one push starts about 7 runs, one for each workflow. Judge the newest push only.

The progress count. It counts the tickets (issues with `Ticket key` in the body) that are not postponed, not parked and not waiting for the maintainer. The search API is refused in a cloud session (403), so the commands below fail there:

```
gh api -X GET search/issues -f q='repo:Hanzamas/RanzVPN is:issue is:closed "Ticket key" in:body -label:postponed -label:needs-triage -label:parked' --jq .total_count
gh api -X GET search/issues -f q='repo:Hanzamas/RanzVPN is:issue is:open "Ticket key" in:body -label:postponed -label:needs-triage -label:parked' --jq .total_count
```

In the cloud, count the open tickets from the lists of the issues instead: the list of "The ready tickets" gives the open ones that carry `ready-for-agent`, and the closed ones are the issues of `issues?state=closed&per_page=100&page=N` with `Ticket key` in the body. Or leave the line out of the report and say so.

## The heartbeat in commands

Rules are in [integrator.md](integrator.md). The commands are these. `<heartbeat>` is the number of the issue `Integrator heartbeat`. The routine prompt names it. If it does not, find it:

```
gh api -X GET search/issues -f q='repo:Hanzamas/RanzVPN is:issue is:open in:title "Integrator heartbeat"' --jq '.items[] | [.number, .title] | @tsv'
```

Look for other integrators. Each row that this prints is a tick comment of another run, not ended, updated in the last 15 minutes. Any row means: stand down.

```
gh api "repos/Hanzamas/RanzVPN/issues/<heartbeat>/comments?since=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)&per_page=100" --jq '.[] | select(.body | startswith("integrator:")) | select(.body | contains("\nended: ") | not) | select(.body | contains("\nrun: <your-run>\n") | not) | [.id, .updated_at, (.body | split("\n") | .[0:3] | join(" / "))] | @tsv'
```

Post your comment. Write it to `/tmp/tick.md` first. The file has the three first lines (`integrator: cloud`, `run: <place>-<UTC start time>`, `alive: <UTC time>`). Keep the comment id in a file, because shell variables do not survive:

```
gh api --method POST repos/Hanzamas/RanzVPN/issues/<heartbeat>/comments -F body=@/tmp/tick.md --jq .id
```

Look again. Run the command above once more and add `| select(.id < <your-comment-id>)` after the last `select`. A row means that another run started first. Edit your comment, add `ended: lost the race` and stand down.

Refresh every 5 minutes, on each `PULSE` of the watcher: write the file again with the new `alive:` time and the report lines, then:

```
gh api --method PATCH repos/Hanzamas/RanzVPN/issues/comments/<comment-id> -F body=@/tmp/tick.md
```

A first tick that launches 12 lanes and reads their pull requests can take more than 15 minutes between two refreshes, and a tick that is not refreshed is taken over (seen on 2026-10-29: the first refresh came 14 minutes and 50 seconds after the post). So start a loop in the background as soon as you have posted: it sleeps 240 seconds, sets the `alive:` line of the tick file to now (`sed -i "s/^alive: .*/alive: $NOW/" tick.md`), patches the comment, and starts again; run it with `run_in_background` and a timeout of 7200000. Edit the report lines in the tick file, never the comment alone, so that the loop does not write an old report over a new one. The loop must stop when you end: make it exit when a stop file exists, create the file, and write `ended:` into the comment. A loop that outlives its tick would keep a dead tick alive for as long as the container runs.

On a PC with PowerShell, the time of 15 minutes ago is `(Get-Date).ToUniversalTime().AddMinutes(-15).ToString("yyyy-MM-ddTHH:mm:ssZ")`.

The lanes of earlier ticks. This prints the `lanes` line of each tick comment of the last 3 hours. The tickets and pull requests that it names are in flight (see "A tick" in [integrator.md](integrator.md)):

```
gh api "repos/Hanzamas/RanzVPN/issues/<heartbeat>/comments?since=$(date -u -d '3 hours ago' +%Y-%m-%dT%H:%M:%SZ)&per_page=100" --jq '.[] | select(.body | startswith("integrator:")) | [.id, .created_at, (.body | split("\n") | map(select(startswith("**lanes"))) | join(" "))] | @tsv'
```

## A tick in the cloud

The steps are those of [integrator.md](integrator.md). The cloud changes these:

1. **Start.** The clone is on the default branch, which may not have these pages yet. Run `git fetch origin integration` and read the pages from there: `git show origin/integration:docs/agents/integrator.md`. Do not commit in the main clone. Lanes work in their own worktrees.
2. **Heartbeat.** With the commands above.
3. **Look.** With the commands of this page, not with `gh pr` and `gh issue`.
4. **Merge and repair.** The REST merge with `sha`. The rerun of a flake is `gh run rerun`.
5. **Launch.** Keep to the lane cap of the routine prompt (default 12), counting the lanes of earlier ticks, and fill every free slot at once. Start each lane as its own agent with isolation `worktree`, or as a Workflow of one lane, because a Workflow runs at most 2 lanes at once in this container and queues the rest. There is no usage tool, and there is no window rule: launch until a command fails with a message about the limit of the plan, then stop launching, write `ended: plan limit` in your comment and end. Do not try again before the next session.
6. **Wait.** Start the watcher below with Monitor (it ends after 30 minutes: start it again, and refresh the heartbeat each time). Never end your turn while a lane of yours is alive or a pull request into `integration` is open and not merged. When the platform ends the session, the lanes end with it. That is a cut-off: the next session resumes from GitHub.
7. **Report.** In the heartbeat comment. A tick that has nothing to do writes the three lines, a line `idle`, and `ended:`.

A tick that stands down costs little: it reads two sections and one issue, and ends.

## The watcher

The cloud version of the pull request watcher prints one line when a pull request becomes clean, conflicting or failed at the same head on two polls in a row. It uses REST only. Start it with Monitor, and start it again when Monitor ends it.

```
#!/bin/bash
repo=Hanzamas/RanzVPN
declare -A seen said
while true; do
  list=$(gh api "repos/$repo/pulls?state=open&base=integration&per_page=100" --jq '.[] | select(.draft | not) | [.number, .head.sha] | @tsv') || list=""
  while IFS=$'\t' read -r n head; do
    [ -z "$n" ] && continue
    state=$(gh api "repos/$repo/pulls/$n" --jq .mergeable_state) || continue
    counts=$(gh api "repos/$repo/actions/runs?head_sha=$head&per_page=100" --jq '[.workflow_runs | group_by(.path)[] | max_by(.id)] | [length, ([.[] | select(.status != "completed")] | length), ([.[] | select(.status == "completed" and .conclusion != "success" and .conclusion != "skipped")] | length)] | @tsv') || continue
    read -r total pending failed <<< "$counts"
    key="$head $state $pending $failed"
    if [ "${seen[$n]}" = "$key" ] && [ "${said[$n]}" != "$key" ]; then
      if [ "$state" = clean ] && [ "$total" -ge 3 ] && [ "$pending" -eq 0 ] && [ "$failed" -eq 0 ]; then
        said[$n]=$key
        echo "PR #$n CLEAN head ${head:0:8} ($total workflows)"
      elif [ "$state" = dirty ]; then
        said[$n]=$key
        echo "PR #$n CONFLICTING head ${head:0:8}"
      elif [ "$pending" -eq 0 ] && [ "$failed" -gt 0 ]; then
        said[$n]=$key
        echo "PR #$n FAILED head ${head:0:8} ($failed workflows failed)"
      fi
    fi
    seen[$n]=$key
  done <<< "$list"
  if [ $((SECONDS - ${last_pulse:-0})) -ge 300 ]; then
    last_pulse=$SECONDS
    echo "PULSE"
  fi
  sleep 30
done
```

A line is a hint. Before you merge, run the two looks of the merge procedure. The line `PULSE` comes every 5 minutes: on it, refresh your heartbeat comment and look again at the lanes, the pull requests and the ready tickets. The poll is every 30 seconds, so a clean or failed pull request is seen within a minute. Each poll makes 1 call plus 2 calls for each open pull request, which is fine for 40 pull requests.

**Wait without ending your turn.** A notice of Monitor reaches the session between two tool calls, and a turn that ends is a tick that ends. When nothing is left to do, block on the output file of the watcher. Its path is `<scratchpad parent>/tasks/<monitor-id>.output` (the notices of Monitor and the task list name the id). One command waits for the next line or for 2 minutes, and then you act and wait again:

```
timeout 120 tail -n0 -F /tmp/claude-0/<project>/<session>/tasks/<monitor-id>.output | head -n1
```

Set the Bash timeout of that call above 120 seconds. Do the useful work between the waits: the lanes, the pull requests, the tickets, the docs.

## Git in a cloud session

- Shallow clone. A merge of `origin/integration` needs the merge base. If `git rev-parse --is-shallow-repository` prints `true`, run `git fetch --unshallow origin` once. Lane worktrees share the objects of the clone.
- Push with `git push origin HEAD:<branch>`. Never force. A push that answers 403 with "Claude doesn't have GitHub access" means that the connection to GitHub is gone. Stop and report it. The maintainer reconnects GitHub in the connectors of claude.ai, and an owner of the account `Hanzamas` installs the Claude GitHub App for the repository if it is missing.
- Write scratch files (a body, a tick file) outside the repository, so that no commit takes them.

## Lanes in the cloud

- Use the template in [lanes/](lanes/README.md). Its rules use these commands, so one script serves both places.
- A lane pushes after every commit, because the container can go at any time.
- A lane watches CI with `gh run watch`, in the background. The template says how.
- When a tick starts after a cut-off, the open pull requests and the pushed branches are the state. Start resume lanes for them as in "After a cut-off" in [integrator.md](integrator.md). A cloud tick cannot resume the Workflow of an earlier tick with `resumeFromRunId`: the journal of that run went with the container. It starts new resume lanes. The lanes that the tick comments of the last 3 hours name are in flight, not cut off: see "The heartbeat in commands".
- The result of a lane is a claim. Read the pull request yourself before you merge it.
- Twelve lanes with the full text of the rules (about 10 KB each) cost much to launch. Write the shared text once into a file of the scratchpad (the authority, the rules, the common text, the state of the moment and the wait rule), and let the prompt of each lane say: read this file with the Read tool first, it binds you as if it stood here, then `YOUR LANE: ...`, and end the prompt with the wait rule. The agents of a session run in the same container and read the scratchpad (done on 2026-10-27 with 14 lanes, all of them read it). The prompt of a lane still carries its own task and the wait rule.
- A lane that has not pushed anything can be stopped (`TaskStop`) without loss. Its worktree stays on disk. Use it to make room for a resume lane, which comes before a new ticket in the order of "Launching lanes". A merge makes every other pull request that shares a file conflict (the proto files, `control.pb.go`, `Control.c`), so expect a wave of conflict lanes after a burst of merges, and merge the pull request that shares the fewest files with the others last.
- The proxy and the permission check of a cloud session are the same for the lanes. A lane reads, pushes, opens its pull request, rewrites the body of its own pull request with `gh api --method PATCH repos/Hanzamas/RanzVPN/pulls/<n> -F body=@<file>` and adds the label `full-ci`. Rule 17 of the lane template has these commands.

## The routine

The maintainer creates the routine from a desktop or web session, with the `schedule` skill. The routine fires a cloud session on a schedule, and the session runs one tick. The default: every hour (cron `7 * * * *`, because a routine cannot fire more often than once an hour; two more routines at `27 * * * *` and `47 * * * *` make it every 20 minutes), at most 12 lanes, merges only into `integration`, never `master`, the heartbeat issue for the lock.

The prompt is short. It points to these pages, so that a change to the pages changes the job without a change to the routine. It sends the tick to the heartbeat first, so that a tick that stands down does not read the whole of both pages:

```
You are the cloud integrator of Hanzamas/RanzVPN. Run one tick.

AUTHORITY: <the words of the maintainer that start this routine, verbatim, with the date>

EXPLICIT PERMISSION: <the actions that the maintainer allows without asking, in this repository only: merge into integration, review of pull requests, create, edit, label, comment on and close tickets, the grill with the recommended answers, to-spec and to-tickets, lanes and their pull requests, ADRs and docs. The one exception: master, which is never touched.>

1. Run git fetch origin integration. Read the section "The integrator heartbeat" of docs/agents/integrator.md and the section "The heartbeat in commands" of docs/agents/integrator-cloud.md, as they are on origin/integration, and do the heartbeat. If you stand down, end.
2. Otherwise read both pages in full, and run one tick as they say.

Heartbeat issue: #<number>
Lane cap: 12
Mode: <dry run | full>
Order of tickets: <the order that the maintainer wants, or none>
Speed rules: <stay alive and react at once; one agent per lane; fill every free slot; no launch window; the wait rule for every lane; a blocker is done when a merged pull request names it; never ask about a merge>
Decisions: <use the recommended answer, record it, and write ASK: only for what the permission does not cover>
```

The integrator never writes the AUTHORITY line or the EXPLICIT PERMISSION paragraph. If the routine has none, the integrator reads and reports and does nothing else. The two tell the tick what the maintainer allows. They do not clear the permission check of the cloud, and no wording of them can. The three layers of "What clears the permission check" do, and layer 1 is set in the allowed tools of the routine, outside the prompt.

**No usage window rule.** A cloud session cannot read the usage of the plan. An earlier rule used time: lanes started only in the first 3 hours after a `window-start` that the tick estimated. The estimate was off by hours, and the rule left the usage at 4% of a window while 52 tickets were ready (2026-10-27). So there is none: the session launches while a slot is free, until a command fails with a message about the limit of the plan. Then it writes `ended: plan limit` and ends, and the next session after the window resets continues.

**First run.** Make the first run a dry run, by hand. In a dry run the tick does the heartbeat and the look, writes the report, and merges nothing, closes nothing and launches nothing. The maintainer reads the heartbeat comment and the run log. That proves in one run the reads with `gh api` and with the MCP tools, and the write and the edit of a comment. Then he sets the mode to `full`.

**One schedule at a time.** While the routine is on, turn off the local scheduled task that resumes work after a usage window. While the maintainer runs the integrator on his PC, turn off the routine. The heartbeat is the safety net, not the plan.

**Set up, in order.**

1. Connect GitHub to claude.ai and install the Claude GitHub App on the account `Hanzamas`, so that a cloud session can push (see "Git in a cloud session").
2. Create the issue `Integrator heartbeat`. Pin it and lock it.
3. Create the routine with the prompt above, the allow rules of layer 1 in its allowed tools (see "What clears the permission check"), mode `dry run`, and run it once by hand.
4. Read the heartbeat comment and the run log. Set the mode to `full`.
5. Turn off the local scheduled task.

## When something fails

| What you see | What it means and what to do |
|---|---|
| An error that names GraphQL | You ran a `gh pr` or `gh issue` command. Use the command of this page. |
| `git push` answers 403 | The GitHub connection is gone. Stop and report. |
| `mergeable` is `null`, state `unknown` | GitHub is still working it out. Ask again in a few seconds. |
| Merge answers 409 | The head moved. Read the pull request again. |
| Merge answers 405 | Not mergeable now. Read the pull request again. |
| Create answers 422 | A pull request for the branch exists, or the branch has no new commit. |
| 403 or 429 with a note about rate limits | Stop the tick, write it in the report, and end. |
| A command that the permission check refused | Do what [integrator.md](integrator.md) says in "What the integrator must not do" and "The report". A refused merge ("Merge Without Review") means that no layer of "What clears the permission check" matches the command as written. Compare the text of the command with the rules, and add the missing layer. A local session merges by hand meanwhile. |
| No heartbeat issue | Stop and report. Without it you cannot know that you are alone. |
