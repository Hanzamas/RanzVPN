# Source formatting

The layout of `src/Cedar`, `src/Mayaqua` (without `3rdparty`), `src/vpnserver`, `src/vpncmd` and `src/vpncmdsys` is set by `.clang-format` at the repository root: attached braces, tabs for indentation, no column limit (line breaks stay as written), no include sorting. Driver sources (`src/SeLow`), third-party code and generated files (`netcfgn.h`, `netcfgx.h`, the `resource.h` files) are not formatted. `python .github/scripts/format_check.py files` prints the exact file list.

The formatter is pinned: clang-format 22.1.8 from PyPI.

```
pip install clang-format==22.1.8
python .github/scripts/format_check.py files | xargs clang-format -i
```

## The one-time reformat (spec #24, pass 11)

`.github/workflows/format.yml` runs on a push to a `format/**` branch. It formats the scoped files and pushes two commits back to that branch:

1. `reformat: layout only (token-identical)`: `.clang-format` as committed. `format_check.py identical` proves that the token stream of every file (comments and whitespace ignored) is unchanged.
2. `reformat: drop braces around single statements (brace-only)`: the same configuration with `RemoveBracesLLVM: true`. `format_check.py braces` proves that the only difference is the deletion of `{ }` pairs that are the body of an `if`, `else`, `for`, `while` or `do` and enclose exactly one statement, with no preprocessor line inside, no `else` that would bind to a different `if`, and no macro that expands to more than one statement.

Nothing is pushed unless both checks pass. The job summary shows line counts per directory before and after each commit. Checker unit tests: `python -m unittest discover -s .github/scripts -p "test_format_check.py"`.
