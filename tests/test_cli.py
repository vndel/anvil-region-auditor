from pathlib import Path
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from anvil_auditor.cli import main


class CliTests(unittest.TestCase):
    def test_json_output_and_exit_code(self):
        with tempfile.TemporaryDirectory() as temp:
            world = Path(temp)
            (world / "region").mkdir()
            (world / "region" / "r.0.0.mca").write_bytes(bytes(8192))
            output = StringIO()
            with redirect_stdout(output):
                code = main([str(world), "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(len(json.loads(output.getvalue())["regions"]), 1)

    def test_csv_header(self):
        with tempfile.TemporaryDirectory() as temp:
            region = Path(temp) / "r.0.0.mca"
            region.write_bytes(bytes(8192))
            output = StringIO()
            with redirect_stdout(output):
                code = main([str(region), "--format", "csv"])
            self.assertEqual(code, 0)
            self.assertIn("kind,path,region_x", output.getvalue())


if __name__ == "__main__":
    unittest.main()
