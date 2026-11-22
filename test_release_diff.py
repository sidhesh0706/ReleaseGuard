import stat
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path

from release_diff import build_manifest, compare_manifests


class ReleaseDiffTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_hashes_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z.txt").write_text("last", encoding="utf-8")
            (root / "a.txt").write_text("first", encoding="utf-8")
            manifest = build_manifest(root)
            self.assertEqual([entry["path"] for entry in manifest["files"]], ["a.txt", "z.txt"])
            self.assertEqual(manifest["files"][0]["kind"], "file")
            self.assertEqual(len(manifest["files"][0]["sha256"]), 64)

    def test_manifest_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            outside = root.parent / "outside.txt"
            outside.write_text("not part of release", encoding="utf-8")
            try:
                (root / "link").symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this platform")
            manifest = build_manifest(root)
            self.assertEqual(manifest["files"][0]["kind"], "symlink")
            self.assertNotIn("sha256", manifest["files"][0])

    def test_manifest_skips_directory_reparse_points(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            linked = root / "linked"
            linked.mkdir()
            (linked / "outside.txt").write_text("outside", encoding="utf-8")
            original_lstat = Path.lstat

            def lstat(path):
                if path == linked:
                    return SimpleNamespace(
                        st_mode=stat.S_IFDIR,
                        st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    )
                return original_lstat(path)

            with patch.object(Path, "lstat", lstat):
                self.assertEqual(build_manifest(root)["files"], [])
                with self.assertRaisesRegex(ValueError, "reparse points excluded"):
                    build_manifest(linked)

    def test_compare_reports_added_removed_changed_and_unchanged(self):
        before = {"schema": 1, "files": [
            {"path": "same.txt", "kind": "file", "size": 1, "mode": 420, "sha256": "a"},
            {"path": "old.txt", "kind": "file", "size": 1, "mode": 420, "sha256": "b"},
            {"path": "changed.txt", "kind": "file", "size": 1, "mode": 420, "sha256": "c"},
        ]}
        after = {"schema": 1, "files": [
            {"path": "same.txt", "kind": "file", "size": 1, "mode": 420, "sha256": "a"},
            {"path": "changed.txt", "kind": "file", "size": 2, "mode": 420, "sha256": "d"},
            {"path": "new.txt", "kind": "file", "size": 1, "mode": 420, "sha256": "e"},
        ]}
        result = compare_manifests(before, after)
        self.assertEqual(result["summary"], {"added": 1, "removed": 1, "changed": 1, "unchanged": 1})
        self.assertEqual(result["added"][0]["path"], "new.txt")
        self.assertEqual(result["removed"][0]["path"], "old.txt")
        self.assertEqual(result["changed"][0]["path"], "changed.txt")

    def test_invalid_manifest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "schema"):
            compare_manifests({"schema": 2, "files": []}, {"schema": 1, "files": []})


if __name__ == "__main__":
    unittest.main()
