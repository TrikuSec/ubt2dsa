from pathlib import Path
import tempfile
import unittest

from scripts.parse_uct import parse_uct_file, parse_status_value


class ParseStatusValueTests(unittest.TestCase):
    def test_released_with_version(self):
        parsed = parse_status_value("released (1.2.3-0ubuntu1)")
        self.assertEqual(parsed.status, "released")
        self.assertEqual(parsed.version, "1.2.3-0ubuntu1")

    def test_plain_status(self):
        parsed = parse_status_value("needed")
        self.assertEqual(parsed.status, "needed")
        self.assertIsNone(parsed.version)


class ParseUctFileTests(unittest.TestCase):
    def test_parses_core_fields(self):
        content = """Candidate: CVE-2026-0001
Priority: high
Description: remote heap issue in parser
upstream_foo: released (3.4.5)
noble_foo: needed
jammy_foo: released (3.4.4)
"""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "CVE-2026-0001"
            path.write_text(content, encoding="utf-8")
            record = parse_uct_file(path, suites={"noble", "jammy"})

        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.cve_id, "CVE-2026-0001")
        self.assertEqual(record.priority, "high")
        self.assertEqual(record.upstream_versions["foo"], "3.4.5")
        self.assertEqual(record.packages["noble"]["foo"].status, "needed")
        self.assertEqual(record.packages["jammy"]["foo"].status, "released")


if __name__ == "__main__":
    unittest.main()
