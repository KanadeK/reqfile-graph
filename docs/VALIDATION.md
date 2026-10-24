# Validation for 0.1.0

Local checks on 2026-10-24, Windows/CPython 3.13.16:

- unittest originally discovered 26 tests: 25 passed, one skipped because this host does not
  grant symbolic-link creation. The real symlink test is enabled on Linux CI;
  the Windows reparse-attribute rejection and case-alias cycle tests ran locally.
- Ruff 0.17.2 lint/format checks passed during development. Final release checks
  rerun them after source/documentation review.
- Covered every supported include form, quoted Unicode filenames, comments,
  continuations, physical line positions, parent-relative paths, cycles, context
  changes, file digests, missing files, root escape, remote/dynamic/absolute paths,
  backslash ambiguity, UTF-8/BOM, malformed syntax, resource caps and DOT escaping.
- The graph edge limit was exercised with 10,001 repeated references; output
  retained 10,000 edges and reported incomplete inventory. Bounded findings kept
  exact observed counts. CLI privacy/read-only tests verified secret markers do
  not appear and source hashes do not change.
- Compared a four-file nested requirements/constraints fixture with pip 26.2.1's
  actual parser. File membership and contexts matched, including `-r` resetting
  context inside a constraints file. All PipSession network requests were blocked.

The release procedure builds sdist/wheel, installs the wheel offline without
dependencies into a clean virtual environment, reruns the tests and README
examples, then verifies installation from a fresh public clone. Publication of
the release follows successful GitHub CI and contributor/identity checks.

CI runs Linux (Python 3.10/3.13), Windows (3.13), macOS (3.13) and Linux quality/
build checks. See Actions for actual results, including platform-specific skips.
Runtime dependencies are zero. The separately installed development toolchain
was checked with pip-audit 2.10.1 with no known vulnerabilities reported at that
time; this does not establish absence of unknown/future vulnerabilities.

The first remote CI run exposed a platform-root alias defect on Windows and macOS:
valid temporary paths were compared against their resolved root before mapping
the explicitly declared root alias. The correction preserves rejection of links
below that root and adds a portable root-alias/escape regression, bringing the
suite to 27 tests. The final release uses the corrected commit and must pass all
CI jobs; the failed historical run is retained as evidence rather than hidden.

Review fixed backslashes being silently consumed by shlex, canonicalized Windows
case aliases, rejected encoding declarations outside the supported subset and
bounded graph edges independently from successfully parsed file count. External
library source was consulted for compatibility but no source was vendored/copied.
