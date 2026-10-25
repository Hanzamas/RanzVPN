export const meta = {
  name: 'lanes-template',
  description: 'Launch lane agents, one per ticket or pull request, each in its own worktree, and return one result per lane.',
  phases: [{ title: 'Lanes', detail: 'one agent per lane in its own worktree' }],
}

// The lane workflow script of the integrator (docs/agents/integrator.md).
// 1. Copy this file out of the repository (the scratchpad of the session, or /tmp) and change meta.name.
// 2. Fill QUOTE, STATE and LANES. Do not commit the filled copy.
// 3. Run it with the Workflow tool: the path of your copy as scriptPath.
// docs/agents/lanes/README.md says how, in one page.
// Keep every string plain: single quotes, no apostrophes, so that no quote ends a string early.

// FILL IN. The words of the maintainer that start this run, verbatim, with their date. In a cloud run
// they are the words that he wrote into the routine. Never write words that he did not write.
const QUOTE = 'FILL IN: Hilmi (the maintainer of Ranz VPN, Hanzamas/RanzVPN) wrote on <date>, in chat or in the routine: "<his words, verbatim>".'

const AUTH = [
  'AUTHORITY: ' + QUOTE,
  'You may create your own branch from origin/integration, commit, push that branch (`git push origin HEAD:<branch>`, never force), open ONE pull request against base `integration` (only where your lane says there is none), and push fix commits until CI is green.',
  'You may merge origin/integration INTO your own branch to clear conflicts.',
  'You may NOT merge any PR, push to master or integration, force-push, delete branches, close or edit issues, or change repository settings; the integrator merges green PRs.',
  'If the permission check blocks a command, stop and report it; never retry it split up or reworded.',
  'Keep every shell command simple: no pipelines that mix gh with awk, sed or other tools.',
].join(' ')

const RULES = [
  'RULES:',
  '(1) Tools over terminal: use Read/Write/Edit/Glob/Grep for every file change; the terminal only for git, gh, CI and tests. Never rewrite a file with a script.',
  '(2) Native, then library, then own code: a Windows-native API first, else a third-party library, own code only if neither exists.',
  '(3) There is no local toolchain for C or Go; CI is the verification loop. Watch CI with ONE watch per push: list the runs of your head with `gh run list --repo Hanzamas/RanzVPN --commit <head-sha>`, then watch the run that still runs and has the most jobs with `gh run watch <run-id> --repo Hanzamas/RanzVPN --interval 60 --compact`. Start it as a background command or with the Monitor tool, never in the foreground: a foreground command ends after 10 minutes in a cloud session and Monitor ends after 30, so start the same command again when it ends before the run does. When the run ends, read the runs of the head again and the failed jobs with the commands of rule 17. Read a failed job with `gh run view --repo Hanzamas/RanzVPN --job <job-id> --log-failed` (the log exists only once its run has finished) or, while the run is still going, `gh api --allow-escape-sequences repos/Hanzamas/RanzVPN/actions/jobs/<job-id>/logs`. Never run `gh run rerun` on a run of another head: it cancels the live run of your PR. Fix forward (up to 6 rounds); never skip, weaken or delete a check or a test.',
  '(4) KNOWN FLAKES: the performance gate (bench-gate.py, microsecond cases such as ip_table_expire_1024, accept_table_16384, ip_table_add_1024 that fail by noise on shared runners), the ETW trace step (etw-trace.ps1: logman could not stop the trace session, 0x80071068, on arm64) and the overlaydns test (an AAAA answer times out, status 1460) fail now and then on code that has nothing to do with them. When the ONLY failing check is one of these and the failing case is in no code you changed, rerun that one failed job once with `gh run rerun <run-id> --repo Hanzamas/RanzVPN --failed` for the run of YOUR current head (the run id of a job: `gh api repos/Hanzamas/RanzVPN/actions/jobs/<job-id> --jq .run_id`), never weaken the gate.',
  '(5) Never edit CONTEXT.md; list any new domain term in the PR body under "New terms".',
  '(6) Read the ticket first (rule 17), plus the ADRs and the code it names, plus CONTEXT.md and docs/agents/domain.md. Every acceptance criterion must be met by a test or CI job, or reported as not met.',
  '(7) Go layout: the Go code is ONE module, go.mod and go.sum at the repository root (module github.com/Hanzamas/RanzVPN). The controller program is the package controllercmd in controller/ (run by `ranz controller`); the one executable is controller/cmd/ranz, a multi-call binary whose subcommands are files that call register(name, run) from init(). The Go CI job is .github/workflows/ranz.yml. When the CI step `Committed files match generation, tidy and gofmt` prints a diff (go mod tidy, or a generated file such as controller/internal/controlpb/control.pb.go), apply exactly that diff: never hand-edit a generated file. Controller API and store use the registries (a new file in controller/internal/api/ calling register(route{...}) from init(), a new file in controller/internal/store/ calling store.RegisterSchema(...)); do not edit api.go or store.go.',
  '(8) Write code that reads like the surrounding code. Never use em dashes.',
  '(9) Each commit message ends with the line: Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com> (Sonnet lanes) or Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com> (Opus lanes). A PR body ends with: 🤖 Generated with [Claude Code](https://claude.com/claude-code)',
  '(10) Your lane is one job only; other lanes run at the same time on neighbouring files. MERGE origin/integration INTO YOUR BRANCH AFTER EVERY CI CYCLE, before you start the next fix round, not only at the end: small conflicts found early are cheap, and you know your change better than anyone.',
  '(11) The SEC-2 quality gates apply: every new function that parses or decodes external bytes needs a fuzz target and a line in .github/quality/fuzz-targets.txt (or an exempt line with a true reason); every new Go package needs a floor line in .github/quality/coverage-floors.txt and every new src/Core module a line there too; clang-tidy, MSVC /analyze and Application Verifier findings in new code must be fixed; a false positive goes into the baseline in .github/quality with its reason. Any CI job that configures or builds the new core needs the steps `Fetch msquic` (.github/scripts/fetch-msquic.ps1) and `Install the nanopb generator` (.github/actions/nanopb).',
  '(12) Line endings: some C files (for example src/vpntest/vpntest.c) are CRLF in the index; edit them with the Edit tool and keep their endings, and check that `git diff --stat origin/integration` shows only your lines.',
  '(13) The move-only check fails an unmarked commit that moves 4 or more lines verbatim between files; never edit .github/move-only-waivers.txt.',
  '(14) THE TEST LISTS ARE AUTOMATIC (PR 338; read its description with `gh api repos/Hanzamas/RanzVPN/pulls/338 --jq .body`). A vpntest test is ONE new .c file in src/vpntest/ that registers itself with RANZ_TEST("name", proc, "help") (src/vpntest/testlist.h; add the tag `core` if the coverage job should run it); nobody edits the table of vpntest.c, the lists of vpntest.ps1, the RANZ_SMOKE_TESTS line of windows.yml or CMakeLists.txt for a test. A test that cannot run in the smoke loop or under AddressSanitizer goes into .github/quality/smoke-exclude.txt or asan-exclude.txt with a reason. A golden family prints `<FAMILY> GOLDEN MODE compare` and is checked generically. If your branch carries edits of the OLD lists (the work in progress of a cut-off lane may), drop those edits when you merge origin/integration, keep your new files, and convert each of your tests to the new registration.',
  '(15) PUSH AFTER EVERY COMMIT with `git push origin HEAD:<branch>`: the session that runs you can be cut off at any moment, and only pushed work survives. Commit early, in small steps; a work-in-progress commit is fine.',
  '(16) Final message: ok (true/false), PR URL, head commit, CI state per job, acceptance criteria met and not met, new terms, any blocked command. ok=false means not done.',
  '(17) COMMANDS. The commands gh pr and gh issue use GraphQL, which a cloud session blocks, so use these gh api commands in their place; they work on the laptop too. A head sha is the full sha of your pushed head (`git rev-parse HEAD`). Read a ticket: `gh api repos/Hanzamas/RanzVPN/issues/<n> --jq .body` and its comments `gh api repos/Hanzamas/RanzVPN/issues/<n>/comments --paginate --jq ".[].body"`. Read a pull request: `gh api repos/Hanzamas/RanzVPN/pulls/<n> --jq .body`. List the newest run of each workflow of your head (an older run that a newer one replaced is hidden; a status other than completed means that the run still goes): `gh api "repos/Hanzamas/RanzVPN/actions/runs?head_sha=<head-sha>&per_page=100" --jq "[.workflow_runs | group_by(.path)[] | max_by(.id)] | .[] | [.id, .path, .status, .conclusion] | @tsv"`. List the jobs of one run: `gh api "repos/Hanzamas/RanzVPN/actions/runs/<run-id>/jobs?per_page=100" --jq ".jobs[] | [.id, .name, .status, .conclusion] | @tsv"`. Open your pull request (only where your lane says there is none), with its body written to a file outside the repository first: `gh api --method POST repos/Hanzamas/RanzVPN/pulls -f title="<title>" -f head=<branch> -f base=integration -F body=@<file> --jq .html_url`. Add the label full-ci to your own pull request: `gh api --method POST repos/Hanzamas/RanzVPN/issues/<pr-number>/labels -f "labels[]=full-ci"`. Nothing else on GitHub is yours to change: no merge, no ticket, no other label.',
  '(18) THE CLOUD. In a cloud session the clone is shallow and the container can be reclaimed at any time. If `git rev-parse --is-shallow-repository` prints true, run `git fetch --unshallow origin` once, before the first merge of origin/integration. Only pushed work survives (rule 15). A command that runs in the foreground ends after 10 minutes.',
].join(' ')

const COMMON = ' Other lanes run at the same time and the usage budget of the account is shared, so work in small steps, push after every commit, and watch CI with the one watch of rule 3 only. Never start a foreground sleep to wait. Keep your edits of functions that other lanes also change (the shared protocol, node and transport files) to hook lines and put your code in new files. A session can be cut off at any moment: every push must be a state that can be resumed.'

// FILL IN. One text with the facts of the moment. Replace it for every run, never stack a second one.
// A lane reads it after its task, and it wins over the task where the two differ.
const STATE = ' STATE of FILL IN the date and time: the repository is public and CI runs on 4-core runners. Merged into integration since the last state: FILL IN the numbers of the pull requests. A pull request runs the FAST set of CI jobs; the FULL set runs on a push to integration, every night, on a pull request with the label `full-ci`, and always on a pull request that changes a sensitive path (the list SENSITIVE in .github/scripts/ci-plan.py). Add the label `full-ci` to your own pull request with the command of rule 17 when your change has C code, once the fast set is green, and fix what the full set finds. Other lanes work at the same time: FILL IN the pull requests and the tickets. Merge origin/integration into your branch after every CI cycle. Keep to one build or test command at a time and never run local builds. The usage window is shared; push after every commit.'

const RESULT = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    pr: { type: 'string' },
    head: { type: 'string' },
    ci: { type: 'string' },
    met: { type: 'array', items: { type: 'string' } },
    notMet: { type: 'array', items: { type: 'string' } },
    newTerms: { type: 'array', items: { type: 'string' } },
    blocked: { type: 'string' },
  },
  required: ['ok', 'pr', 'ci'],
}

// One lane. Copy it into LANES and change it. A lane object has:
//   key    a short name, used for the label and the result
//   model  'opus' (the C data path, crypto, drivers, hard design) or 'sonnet' (Go, UI, CLI, docs, CI)
//   skip   true leaves the lane out of the run; keep a finished lane in the array with skip: true
//   task   what the lane does, in plain words (see the README for the text of a resume lane)
const EXAMPLE_LANE = {
  key: 'example',
  model: 'sonnet',
  skip: true,
  task: 'YOUR LANE: implement ticket #NNN (KEY-N: the title of the ticket) in Hanzamas/RanzVPN, exactly as its acceptance criteria say. Its blockers are merged. Read the ticket first, then the ADRs and the code that it names. Create your branch `area/NNN-short-name` from origin/integration, push it with `git push origin HEAD:area/NNN-short-name`, and open ONE pull request against `integration` titled after the ticket key and name, with the line "Closes #NNN" in the body and a table of the acceptance criteria (criterion, test or job). Add the label `full-ci` once the fast set is green, when the change has C code. Push after every commit.',
}

const LANES = []

async function lane(l) {
  const prompt = AUTH + '\n\n' + RULES + '\n\n' + l.task + COMMON + STATE
  const opts = { label: 'lane:' + l.key, phase: 'Lanes', schema: RESULT, model: l.model, isolation: 'worktree' }
  if (l.model === 'sonnet') opts.effort = 'max'
  try {
    return await agent(prompt, opts)
  } catch (e) {
    log('lane ' + l.key + ' failed to start (' + String(e).slice(0, 120) + '), retrying once')
    return await agent(prompt, opts)
  }
}

phase('Lanes')
const ACTIVE = LANES.filter(l => !l.skip)
if (ACTIVE.length > 0 && (QUOTE.includes('FILL IN') || STATE.includes('FILL IN'))) {
  throw new Error('Fill in QUOTE and STATE before you run lanes (docs/agents/lanes/README.md).')
}
for (const l of ACTIVE) {
  if (l.model !== 'opus' && l.model !== 'sonnet') throw new Error('Lane ' + l.key + ' needs the model opus or sonnet.')
  if (ACTIVE.filter(o => o.key === l.key).length > 1) throw new Error('Two lanes have the key ' + l.key + '.')
}
if (ACTIVE.length > 6) log('WARNING: ' + ACTIVE.length + ' lanes at once. The pace rule is about 5 (docs/agents/integrator.md).')
const results = await parallel(ACTIVE.map(l => () => lane(l)))
return ACTIVE.map((l, i) => ({ lane: l.key, model: l.model, result: results[i] }))
