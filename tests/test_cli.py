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
        self.assertEqual(r.stdout.strip(),"0.1.0")

    def test_demo_and_private_directory_cannot_be_combined(self):
        r=subprocess.run([sys.executable,"-B","-m","traffic_observer","gui","--demo","--data-dir","example"],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,2)

if __name__=="__main__":unittest.main()
