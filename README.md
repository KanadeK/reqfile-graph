# reqfile-graph

Audit the local files included by pip requirements and constraints before handing
off a source bundle. Find missing files, cycles and references outside the bundle
without installing packages, fetching URLs or printing requirement values.

```text
OK: 3 files, 2 includes, 0 errors, 0 warnings
file "common.txt" contexts=requirement
file "constraints.txt" contexts=constraint
file "requirements.txt" contexts=requirement
```

Useful when a requirements tree works on one machine but a nested file is absent
from a release archive or depends on a local path. pip and uv already detect many
installation errors, including cycles. This tool adds an explicit bounded file
inventory, source-line graph, file digests and root-containment policy without
running an installer. It is not a package resolver or a requirements validator.

The [pip format reference](https://pip.pypa.io/en/stable/reference/requirements-file-format/)
documents includes and cautions that its full syntax belongs to pip.
[pip #6112](https://github.com/pypa/pip/issues/6112) and
[uv #3180](https://github.com/astral-sh/uv/issues/3180) illustrate directory-dependent
local install references; those are flagged here rather than incorrectly resolved.

## Install and remove

Python 3.10+ and Git are required. The initial version is distributed through
GitHub, not PyPI. There are no third-party runtime dependencies.

```sh
git clone https://github.com/KanadeK/reqfile-graph.git
cd reqfile-graph
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS or
`.venv\Scripts\Activate.ps1` on Windows PowerShell, then:

```sh
python -m pip install .
reqfile-graph --version
```

If activation is restricted, use `.venv\Scripts\python.exe` and
`.venv\Scripts\reqfile-graph.exe` directly; no policy change is required. Building
may download setuptools. All installed audit commands work offline.

Uninstall with `python -m pip uninstall reqfile-graph`. The program creates no
cache or hidden settings. Deactivate and remove the clone/venv when no longer
needed; remove any reports you redirected yourself.

## Complete example

From the cloned repository:

```sh
reqfile-graph examples/good/requirements.txt --root examples/good --format json
# exit 0: three files, two includes

reqfile-graph examples/bad/requirements.txt --root examples/bad --format json
# exit 1: include-cycle, missing-file, remote-reference
```

The examples are audited as files; no packages from them are installed. To check
your bundle, pass entry paths relative to your **current directory**. Includes
are then resolved relative to the file containing them, not the current directory:

```sh
reqfile-graph bundle/requirements.txt bundle/dev.txt --root bundle --format json
```

`--root` is required and must identify a real, existing bundle directory. Use its
canonical path when your working tree is reached through a directory alias.
Reported filenames are relative to this canonical root.

For a visual file graph:

```sh
reqfile-graph examples/good/requirements.txt --root examples/good --format dot > graph.dot
# Optional, if Graphviz is already installed:
dot -Tsvg graph.dot -o graph.svg
```

DOT output still uses the normal exit code but contains only the graph; use JSON
to inspect findings. Blocked/unread files are shown as unresolved nodes without
their original target values.

## Supported include syntax

One include directive per logical line:

```text
-r base.txt
-rbase.txt
--requirement base.txt
--requirement=base.txt
-c constraints.txt
-cconstraints.txt
--constraint constraints.txt
--constraint=constraints.txt
-r "files with spaces.txt"
-r nested/../base.txt
```

Forward slashes work on all supported operating systems. Quoted filenames,
UTF-8 names, BOM, CRLF, whitespace-prefixed `#` comments and single-backslash
physical line continuations are supported. Comments are removed after joining
lines. A hash without preceding whitespace remains part of a filename.

Each `-r` sets the child to requirements context; each `-c` sets it to constraints
context, including when nested inside a constraints file. A file used in both
contexts is read once and inspected in each context. Edges retain source context,
kind and the 1-based starting physical line. Repeated entry paths are harmless.

Abbreviated options, multiple include options on one line, include options mixed
with package statements, dangling continuations and ambiguous repeated trailing
backslashes fail explicitly. Non-include statements are counted, not parsed or
validated. Python encoding declarations other than UTF-8 are rejected.

## Findings and privacy

Errors include missing/nonregular files, cycles, absolute or drive-relative paths,
remote/file URL includes, dynamic variables, globs, backslashes, linked paths,
root escape, unreadable UTF-8 and resource limits. References containing `$`,
`%NAME%` or a leading `~` are considered dynamic and never expanded. `..` is
allowed only when the final path stays inside the root. Symlinks and Windows
reparse points below the root are rejected even when they point back inside it.

Recognizable editable and local install statements receive
`local-install-statement` warnings. The tool does not resolve their working
directory or assert that their targets are bundled. `--warnings-as-errors` makes
those warnings fail the gate. Other package lines, index settings, hashes and
environment markers are not evaluated; URLs in package statements are not fetched.

Output includes file paths, file byte counts/SHA-256 digests, contexts, statement
counts, include edges and findings. It omits package specifications, index URLs,
credential-bearing remote include targets and variable names. Filenames and file
digests may still be sensitive; the report is not anonymized.

Exit **0**: no errors and the warning policy passed. Exit **1**: audit finding or
incomplete inventory. Exit **2**: invalid command usage/options. JSON schema
version 1 includes `ok`, `complete`, `files`, `edges`, `total_bytes`, exact observed
finding counts and a bounded `findings` list. `complete=false` means at least one
error prevented a clean inventory of the supported include graph.

```python
from reqfile_graph import audit

report = audit(["bundle/requirements.txt"], root="bundle")
assert report["ok"], report["findings"]
```

## Limits in 0.1.0

Default limits: 512 successfully parsed files, 64 include hops, 1 MiB per file,
16 MiB total input, 10,000 graph edges and 1,000 stored findings. CLI flags adjust
file/depth/byte/finding limits; depth is capped at 128 and edges at 10,000.
Finding storage truncation preserves observed counts. Resource-limit failures
always produce a nonzero exit; counts describe the portion actually inspected.

An empty requirements file is a valid inventory node. Passing this audit proves
neither dependency compatibility, reproducibility, license safety nor that pip
installation will work offline. Full pip syntax, package versions, package-local
file references and build behavior are outside scope. Inputs must remain stable:
this read-only application does not lock a tree or provide an OS sandbox against
concurrent malicious filesystem changes.

See [design](docs/DESIGN.md), [validation](docs/VALIDATION.md),
[contribution guide](CONTRIBUTING.md), [security policy](SECURITY.md) and [MIT license](LICENSE).

## 中文说明

在交付 requirements 文件目录前，检查 `-r` / `-c` 引用是否齐全、是否循环、
是否越过声明的根目录，并生成带来源行号的 JSON 或 DOT 图。只读本地文件，
不安装依赖、不访问远程 URL、不展开环境变量，也不输出包版本行或带凭据的 URL。

运行 `reqfile-graph examples/good/requirements.txt --root examples/good --format json`
体验正常流程；bad 示例应返回退出码 1。入口参数相对于当前目录，嵌套引用相对于
所在文件。引用中请使用正斜杠。当前仅检查引用图，不校验完整 pip 语法，不保证
依赖可安装、可复现或能离线安装；本地安装路径会产生警告。
