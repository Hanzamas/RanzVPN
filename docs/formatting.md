# Source formatting

The layout of `src/Cedar`, `src/Mayaqua` (without `3rdparty`), `src/ranz-node`, the new core `src/Core` and its test program `src/coretest` is set by `.clang-format` at the repository root: attached braces, tabs for indentation, no column limit (line breaks and one-line statements stay as written), no include sorting. Trailing comments and `#define` values of consecutive lines are aligned with spaces; a comment on its own line follows the indentation of its code. Driver sources (`src/SeLow`), the test and fuzz programs (`src/vpntest`, `src/fuzz`) and third-party code are not formatted. `python .github/scripts/format_check.py files` prints the exact file list.

The formatter is pinned: clang-format 22.1.8 from PyPI.

```
pip install clang-format==22.1.8
python .github/scripts/format_check.py files | xargs clang-format -i
```

The `format check` job of `.github/workflows/windows.yml` runs the pinned clang-format with `--dry-run --Werror` on the same file list and fails when a file is not formatted. Run the two commands above before pushing a change to a file in the scope. The job runs with the rest of `windows.yml`: on every push to `master` or `integration`, and on a pull request that changes a path the C build or its checks read (it is part of the fast set of a pull request, see the header comment of `windows.yml`). A pull request that changes only `controller/`, `proto/`, `docs/` or `*.md` files does not run it; the header comment of `windows.yml` lists the paths it leaves out.

## The one-time reformat (spec #24, pass 11)

`.github/workflows/format.yml` runs on a push to a `format/**` branch. It formats the scoped files and pushes two commits back to that branch:

1. `reformat: layout only (token-identical)`: `.clang-format` as committed. `format_check.py identical` proves that the token stream of every file (comments and whitespace ignored) is unchanged.
2. `reformat: drop braces around single statements (brace-only)`: the same configuration with `RemoveBracesLLVM: true`. `format_check.py braces` proves that the only difference is the deletion of `{ }` pairs that are the body of an `if`, `else`, `for`, `while` or `do`, lie outside any preprocessor directive (a `#define` body keeps its braces) and enclose exactly one statement that is not a declaration, with no `else` that would bind to a different `if` (on any path through the `#if` groups after the pair: the first token of every arm, and the token after the group when an arm is empty, there is no `#else`, or the pair ends an arm) and no macro that expands to more than one statement outside a nested `{ }`. Such a macro (one with a `;`, an `if` or an `else` outside brackets, or that uses another such macro there) also counts as an `else` in the places after the pair, since its expansion can start with one. A preprocessor line may only sit inside a nested bracket group, and each `#if` arm must close the brackets it opens, so the body is one statement whichever arm is compiled.

Nothing is pushed unless both checks pass. The job summary shows line counts per directory before and after each commit, and the `format-out` artifact holds the commits as patches. Checker unit tests: `python -m unittest discover -s .github/scripts -p "test_format_check.py"`.
