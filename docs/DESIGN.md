# Scope and acceptance

Target: release engineers and maintainers moving a tree of requirements files
between machines or into source archives. The workflow is declare a bundle root
and entry files → audit the graph → inspect source locations → include/fix files
or remove nonportable references → rerun. No package installation is performed.

Acceptance: inventory nested local requirements/constraints with physical source
lines and digests; preserve context changes; detect cycles/missing references;
reject paths outside root, links/reparse points, remote/dynamic references and
unsafe ambiguous include forms; do not print source values; fail resource limits;
preserve input hashes; install from a clean wheel and run the README examples.

Architecture: the lexical layer joins continuations and classifies only include
directives and recognizable local-install statements. Package lines are counted
then discarded. The graph walker applies path policy before opening an include,
uses an active file stack for cycles and caches parsed content by canonical path.
Visited states include the requirements/constraints context. Outputs retain only
safe relative graph metadata; JSON escaping is also used for DOT labels.

Alternative tools: pip/uv resolve dependencies and already detect recursion.
flake8-requirements compares imports to declared requirements. This project
provides a bounded read-only bundle inventory, not another resolver or parser.
The accepted lexical subset was checked against pip 26.2.1 on synthetic local
fixtures, with network requests blocked. pip is not an application dependency.

Review focus: symlink escapes, Windows drive/case/backslash handling, source-line
accuracy, combined/abbreviated include forms, context resets and accidentally
echoing credentials from URLs or exception messages.
