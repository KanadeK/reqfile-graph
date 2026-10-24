from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from reqfile_graph import audit, to_dot
from reqfile_graph.lex import statements


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "bundle"
        self.root.mkdir()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
        return path

    def codes(self, report):
        return {item["code"] for item in report["findings"]}

    def test_inventory_contexts_counts_and_digests(self):
        main = self.write("requirements.txt", "-r base.txt\n-c pin.txt\napp==1\n")
        base = self.write("base.txt", "lib>=1\n")
        self.write("pin.txt", "lib<2\n")
        report = audit([main], root=self.root)
        self.assertTrue(report["ok"], report)
        self.assertEqual(len(report["files"]), 3)
        self.assertEqual([edge["kind"] for edge in report["edges"]], ["requirement", "constraint"])
        node = next(x for x in report["files"] if x["path"] == "base.txt")
        self.assertEqual(node["sha256"], hashlib.sha256(base.read_bytes()).hexdigest())
        self.assertEqual(node["statement_count"], 1)
        self.assertNotIn("app==1", json.dumps(report))

    def test_same_file_can_have_two_contexts(self):
        main = self.write("r.txt", "-r base.txt\n-c base.txt\n")
        self.write("base.txt", "lib==1\n")
        result = audit([main], root=self.root)
        base = next(x for x in result["files"] if x["path"] == "base.txt")
        self.assertEqual(base["contexts"], ["requirement", "constraint"])
        self.assertEqual(len(result["files"]), 2)

    def test_requirement_include_resets_constraint_context(self):
        main = self.write("r.txt", "-c pin.txt\n")
        self.write("pin.txt", "-r base.txt\n")
        self.write("base.txt", "lib==1\n")
        result = audit([main], root=self.root)
        edge = result["edges"][1]
        self.assertEqual(edge["source_context"], "constraint")
        self.assertEqual(edge["kind"], "requirement")
        base = next(x for x in result["files"] if x["path"] == "base.txt")
        self.assertEqual(base["contexts"], ["requirement"])

    def test_all_include_forms_and_quoted_unicode(self):
        for include in (
            "-r base.txt",
            "-rbase.txt",
            "--requirement base.txt",
            "--requirement=base.txt",
            "-c base.txt",
            "-cbase.txt",
            "--constraint base.txt",
            "--constraint=base.txt",
        ):
            with self.subTest(include=include):
                main = self.write("r.txt", include + "\n")
                self.write("base.txt", "lib==1\n")
                self.assertTrue(audit([main], root=self.root)["ok"])
        main = self.write("r.txt", '-r "含空格 文件.txt"\n')
        self.write("含空格 文件.txt", "lib==1\n")
        self.assertTrue(audit([main], root=self.root)["ok"])

    def test_continuations_comments_and_physical_line_numbers(self):
        main = self.write(
            "r.txt", "# comment\\\n\n-r \\\n  base.txt # explanation\r\nlib==1 # note\n"
        )
        self.write("base.txt", "other==2\n")
        result = audit([main], root=self.root)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["edges"][0]["line"], 3)
        self.assertEqual(len(result["files"]), 2)

    def test_include_resolution_uses_parent_file_directory(self):
        main = self.write("r.txt", "-r nested/base.txt\n")
        self.write("nested/base.txt", "-c ../pins.txt\n")
        self.write("pins.txt", "lib==1\n")
        report = audit([main], root=self.root)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["edges"][1]["target"], "pins.txt")

    def test_declared_root_alias_maps_to_canonical_root_before_link_checks(self):
        self.write("r.txt", "-r base.txt\n")
        self.write("base.txt", "lib==1\n")
        alias = self.root.parent / "platform-root-alias"
        actual_resolve = Path.resolve

        def resolve(path, *args, **kwargs):
            if path == alias:
                return actual_resolve(self.root, *args, **kwargs)
            return actual_resolve(path, *args, **kwargs)

        # Reproduce /var -> /private/var or Windows short-name root resolution
        # without requiring symlink creation privileges on the local host.
        with mock.patch.object(Path, "resolve", resolve):
            result = audit([alias / "r.txt"], root=alias)
            escaped = audit([alias / "../outside.txt"], root=alias)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["files"]), 2)
        self.assertIn("outside-root", self.codes(escaped))

    def test_cycle_is_reported_without_infinite_recursion(self):
        main = self.write("a.txt", "-c b.txt\n")
        self.write("b.txt", "-r a.txt\n")
        report = audit([main], root=self.root)
        self.assertIn("include-cycle", self.codes(report))
        self.assertEqual(report["findings"][0]["chain"], ["a.txt", "b.txt", "a.txt"])
        self.assertFalse(report["complete"])

    def test_missing_include_and_invalid_root(self):
        main = self.write("r.txt", "-r gone.txt\n")
        self.assertIn("missing-file", self.codes(audit([main], root=self.root)))
        self.assertIn("invalid-root", self.codes(audit([main], root=self.root / "missing")))
        self.assertIn("no-entries", self.codes(audit([], root=self.root)))

    def test_outside_root_is_never_opened(self):
        outside = self.root.parent / "outside.txt"
        outside.write_text("PRIVATE_OUTSIDE", encoding="utf-8")
        main = self.write("r.txt", "-r ../outside.txt\n")
        original = Path.open
        opened = []

        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path, outside)
            opened.append(path)
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "open", guarded):
            result = audit([main], root=self.root)
        self.assertIn("outside-root", self.codes(result))
        self.assertEqual(opened, [main.resolve()])
        self.assertNotIn("PRIVATE_OUTSIDE", json.dumps(result))

    def test_remote_absolute_and_dynamic_targets_are_not_printed(self):
        main = self.write(
            "r.txt",
            "-r https://USER:PRIVATE_PASSWORD@example.invalid/t.txt\n"
            "-r ${PRIVATE_VARIABLE}/r.txt\n-r C:/outside.txt\n-r /etc/private.txt\n",
        )
        with mock.patch("socket.create_connection", side_effect=AssertionError("No network")):
            report = audit([main], root=self.root)
        self.assertEqual(
            self.codes(report), {"remote-reference", "dynamic-reference", "absolute-reference"}
        )
        serialized = json.dumps(report) + to_dot(report)
        for secret in ("PRIVATE_PASSWORD", "PRIVATE_VARIABLE", "private.txt", "example.invalid"):
            self.assertNotIn(secret, serialized)
        self.assertTrue(all(edge["target"] is None for edge in report["edges"]))

    def test_backslashes_cannot_be_silently_removed_by_shlex(self):
        main = self.write("r.txt", "-r sub\\base.txt\n")
        self.write("subbase.txt", "wrong-but-existing==1\n")
        result = audit([main], root=self.root)
        self.assertIn("nonportable-reference", self.codes(result))
        self.assertEqual(len(result["files"]), 1)

    def test_symlinks_are_rejected_inside_and_outside_root(self):
        actual = self.write("actual.txt", "lib==1\n")
        link = self.root / "alias.txt"
        try:
            os.symlink(actual, link)
        except OSError:
            self.skipTest("Creating symlinks is unavailable on this host")
        outside = self.root.parent / "outside.txt"
        outside.write_text("PRIVATE_OUTSIDE", encoding="utf-8")
        os.symlink(outside, self.root / "outside-alias.txt")
        main = self.write("r.txt", "-r alias.txt\n-r outside-alias.txt\n")
        result = audit([main], root=self.root)
        self.assertIn("linked-path", self.codes(result))
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["error_count"], 2)

    def test_windows_reparse_attribute_is_rejected(self):
        main = self.write("r.txt", "lib==1\n")
        info = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
        with mock.patch.object(Path, "lstat", return_value=info):
            self.assertIn("linked-path", self.codes(audit([main], root=self.root)))

    @unittest.skipUnless(os.name == "nt", "Case-insensitive identity applies to Windows")
    def test_windows_case_alias_does_not_hide_cycle(self):
        main = self.write("Main.txt", "-r MAIN.TXT\n")
        report = audit([main], root=self.root)
        self.assertIn("include-cycle", self.codes(report))
        self.assertEqual(len(report["files"]), 1)

    def test_invalid_include_forms_fail_closed(self):
        for text in (
            "-r",
            "--requirement=",
            '-r "unfinished',
            "-r a.txt -c b.txt",
            "--req base.txt",
            "lib==1 -r base.txt",
            "-r a*.txt",
        ):
            with self.subTest(text=text):
                main = self.write("r.txt", text + "\n")
                self.assertFalse(audit([main], root=self.root)["ok"])

    def test_dangling_and_ambiguous_continuations(self):
        for text in ("-r \\\n", "-r base.txt\\\\\n"):
            with self.subTest(text=text):
                self.assertFalse(audit([self.write("r.txt", text)], root=self.root)["ok"])

    def test_utf8_bom_bad_encoding_and_declared_nonutf8(self):
        path = self.write("r.txt", "\ufefflib==1\n")
        self.assertTrue(audit([path], root=self.root)["ok"])
        path.write_bytes(b"\xff\n")
        self.assertIn("unreadable-file", self.codes(audit([path], root=self.root)))
        path.write_text("# coding: cp1252\nlib==1\n", encoding="utf-8")
        self.assertIn("unsupported-encoding", self.codes(audit([path], root=self.root)))

    def test_local_install_statement_warning(self):
        main = self.write("r.txt", "-e.\nlib @ file:///tmp/local.whl\n./local.whl\n")
        result = audit([main], root=self.root)
        self.assertTrue(result["ok"])
        self.assertEqual(result["warning_count"], 3)
        self.assertFalse(audit([main], root=self.root, warnings_as_errors=True)["ok"])

    def test_file_depth_and_byte_limits(self):
        main = self.write("a.txt", "-r b.txt\n")
        self.write("b.txt", "-r c.txt\n")
        self.write("c.txt", "lib==1\n")
        for options, expected in [
            ({"max_files": 1}, "file-limit"),
            ({"max_depth": 1}, "depth-limit"),
            ({"max_file_bytes": 2}, "byte-limit"),
            ({"max_total_bytes": 10}, "byte-limit"),
        ]:
            with self.subTest(options=options):
                result = audit([main], root=self.root, **options)
                self.assertFalse(result["ok"])
                self.assertIn(expected, self.codes(result))
        for options in ({"max_files": 0}, {"max_depth": 129}):
            with self.assertRaises(ValueError):
                audit([main], root=self.root, **options)

    def test_findings_truncation_retains_failure_and_counts(self):
        main = self.write("r.txt", "-r ${SECRET}/x\n" * 15)
        report = audit([main], root=self.root, max_findings=2)
        self.assertEqual(report["error_count"], 15)
        self.assertEqual(len(report["findings"]), 2)
        self.assertTrue(report["findings_truncated"])

    def test_edge_limit_bounds_graph_even_for_repeated_references(self):
        main = self.write("r.txt", "-r base.txt\n" * 10_001)
        self.write("base.txt", "lib==1\n")
        report = audit([main], root=self.root)
        self.assertIn("edge-limit", self.codes(report))
        self.assertEqual(len(report["edges"]), 10_000)

    def test_dot_escaping(self):
        name = 'quotes"\n; injected'
        graph = to_dot({"files": [{"path": name}], "edges": []})
        self.assertIn(json.dumps(name, ensure_ascii=False), graph)
        self.assertEqual(len(graph.splitlines()), 4)

    def test_empty_files_and_repeated_entry_are_finite(self):
        main = self.write("r.txt", "")
        result = audit([main, main], root=self.root)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["files"]), 1)

    def test_cli_privacy_exit_codes_and_preserved_bytes(self):
        main = self.write("r.txt", "-r https://user:PRIVATE_TOKEN@example.invalid/t.txt\n")
        before = hashlib.sha256(main.read_bytes()).hexdigest()
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "reqfile_graph",
                str(main),
                "--root",
                str(self.root),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["error_count"], 1)
        self.assertNotIn("PRIVATE_TOKEN", proc.stdout + proc.stderr)
        self.assertNotIn("example.invalid", proc.stdout + proc.stderr)
        self.assertEqual(before, hashlib.sha256(main.read_bytes()).hexdigest())
        bad = subprocess.run(
            [
                sys.executable,
                "-m",
                "reqfile_graph",
                str(main),
                "--root",
                str(self.root),
                "--max-depth",
                "129",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(bad.returncode, 2)

    def test_examples(self):
        examples = Path(__file__).resolve().parents[1] / "examples"
        good = audit([examples / "good/requirements.txt"], root=examples / "good")
        bad = audit([examples / "bad/requirements.txt"], root=examples / "bad")
        self.assertTrue(good["ok"])
        self.assertEqual(len(good["files"]), 3)
        self.assertEqual(self.codes(bad), {"include-cycle", "missing-file", "remote-reference"})

    def test_comments_do_not_strip_hash_inside_filename(self):
        parsed = statements("-r base#1.txt # ignored\n")
        self.assertEqual(parsed[0].target, "base#1.txt")


if __name__ == "__main__":
    unittest.main()
