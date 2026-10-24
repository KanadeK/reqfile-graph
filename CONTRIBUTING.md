# Contributing

Please open an issue with a minimal synthetic reproducer before proposing a change.
Do not include private reports, credentials or personal data. Include the tool and
Python versions, expected behavior and actual behavior.

```sh
python -m venv .venv
# Activate .venv (see README), then:
python -m pip install -e . ruff==0.17.2 build
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
python -m build
```

The initial release is maintained with one account as the sole Git commit
author and committer. External pull requests are not merged in this release
workflow; issues and suggestions are welcome. Third-party copyright and license
notices must always be retained. CI only tests/builds and never commits changes.

Small, documented behaviors and regression tests are preferred. Keep runtime
dependencies at zero unless there is a clear need and a license/security review.
