# tools/split

Re-runnable god-file split for issue #29 (structural refactor).

- `split-map.json`: for each god file, the new files and the top-level definitions each receives
  (exact names, then patterns), and the names that stay in the god file on purpose. A file entry
  may carry a short `group` label for its commit subject.
- `apply_split.py`: applies the map. It moves whole top-level blocks verbatim (with the comment
  written directly above them, in their original order), keeps every file-local symbol with all of
  its users, puts macros and types shared by several files of a module into `<Module>Internal.h`,
  moves the prototypes that only the module uses from `<Module>.h` to `<Module>Internal.h`, and
  reports what the map does not place, what a file-local symbol keeps back and which map entries
  match nothing.
- `splitlib.py`: the top-level C parser the tool uses.

The move-only checker that proves the commits is `.github/scripts/move-only-check.py`.

## Commit mode

`--commit` writes the split of each module as a sequence of commits of the #29 kinds, and runs the
move-only checker on each commit as soon as it is made. It stops at the first failure and leaves
the commits made so far in place; at the end it checks the whole range once more.

1. `split: <God>.c shared macros and types to <Module>Internal.h`: the macros and types that
   several files of the module use move to the NEW internal header (include guard, comment
   header); the god file gains only the one `#include` of it, at the end of its preamble
   (#29 open question 12 (a)). No commit when nothing is shared.
2. `split: <God>.c <group> to <File>.c`: one commit per destination file, in map order. A new file
   starts with the god file's comment header style (file name and the map's description), then
   the preprocessor lines of the god file's preamble that the moved code needs: project includes
   whose declarations, macros or struct fields the moved code (or the internal header) does not
   use are left out; the god file's own header, the internal header, system headers, other
   directives and conditional blocks stay; comment lines of the preamble are left out, because
   the checker allows no comment after the first directive. When git diff would not show the move
   as deletions only from the god file (git's myers diff gives up on the minimal script next to
   large deletions), the group moves in parts, `(1/n)` ... `(n/n)`, each appended to the end of the
   destination. A part never cuts a unit: the items that a file-local symbol ties together, with
   the file's own macros and types that they use, move in one commit, so that every part compiles.
   A unit that git diff does not show as deletions only even when it moves alone is reported; the
   checker would reject its commit, so the map keeps it in the god file.
3. `header: module-only prototypes move from <Module>.h to <Module>Internal.h`: prototypes that no
   file outside the module names. When the internal header is new here, the commit creates it and
   adds its `#include` to every `.c` file of the module.
4. `linkage: <Module> module functions that one file uses become static` (only with `--linkage`):
   `static` for every function that only its own file uses and defines before its first use; its
   prototype is deleted from the module's headers.

No CMake edit is made: Cedar and Mayaqua glob `*.c`. Every commit ends with `Refs #29` and the
co-author line.

```
git switch -c split-pass origin/integration
python -I tools/split/apply_split.py --dry-run --explain     # the commits it would make, and the drift
python -I tools/split/apply_split.py --commit [--linkage] [--module Hub ...]
python -I C:/Users/hilmi/ranz-devkit/devcheck.py .          # compile check (syntax only)
```

The tool proves only the move rules. Compile each commit (devcheck or CI) and keep the harness
goldens unchanged.

## Drift

When the tree has drifted from the map, the tool warns and goes on; it never stops on the map:

- a map name or pattern that matches no definition (deleted or renamed) places nothing, and the
  warning names the closest unmapped definitions;
- a definition that no map entry places stays in the god file and is listed (an `#if` region that
  defines no name, such as a static assertion, stays too and is only noted);
- a group of definitions that a file-local symbol ties to users in other files stays in the god
  file and is listed (`--explain` shows which symbol ties which users);
- a god file that is missing or does not parse skips its module, and the other modules still split;
- `--drift-json FILE` writes all of it per module (unplaced, kept_back, stale_names,
  dead_patterns, notes);
- `--reference REV` (for example the last split commit) lists the definitions that land in another
  file than in REV.

Commit a map fix on its own, before the split commits, so that the checker sees only moves.
