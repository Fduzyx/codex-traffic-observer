import subprocess
import sys
import unittest

class CliTests(unittest.TestCase):
    def test_help_does_not_import_or_start_collectors(self):
        r=subprocess.run([sys.executable,"-B","-m","traffic_observer","--help"],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0)
        self.assertIn("collect",r.stdout)

    def test_version_works_without_a_window(self):
        r=subprocess.run([sys.executable,"-B","-m","traffic_observer","--version"],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0)
        self.assertEqual(r.stdout.strip(),"0.2.0")

    def test_demo_and_private_directory_cannot_be_combined(self):
        r=subprocess.run([sys.executable,"-B","-m","traffic_observer","gui","--demo","--data-dir","example"],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,2)

    def test_demo_cannot_open_a_real_ledger(self):
        r=subprocess.run([sys.executable,"-B","-m","traffic_observer","gui","--demo","--mihomo-db","example.db"],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,2)
        self.assertIn("cannot be combined", r.stderr)

    def test_explicit_ledger_and_unknown_page_are_supported(self):
        from traffic_observer.__main__ import parser
        args=parser().parse_args(["gui","--data-dir","example","--mihomo-db","example.db","--view","unknown"])
        self.assertEqual(args.view,"unknown")
        self.assertEqual(args.mihomo_db.name,"example.db")

if __name__=="__main__":unittest.main()
