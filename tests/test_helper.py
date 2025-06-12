import unittest
import tempfile
import os
import shutil
import io
import sys
from typing import Dict, List

# Adjust path to import fwsimple from the parent directory
# This ensures that fwsimple is importable when tests are run.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fwsimple.firewall import Firewall

class EngineTestCaseBase(unittest.TestCase):
    engine_name_for_firewall_init = None # Subclasses can override this

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _get_engine_specific_firewall_args(self) -> Dict:
        """
        Returns engine-specific arguments for Firewall constructor.
        """
        if self.engine_name_for_firewall_init:
            return {'engine_name': self.engine_name_for_firewall_init}
        return {}

    def _process_dry_run_output(self, output_lines: List[str]) -> List[str]:
        """
        Allows subclasses to specifically process the raw output lines.
        Default is to return lines that are not empty after stripping.
        """
        return [line for line in output_lines if line.strip()]

    def _run_fwsimple_dry_run(self, config_content: str, rules_files: Dict[str, str]) -> List[str]:
        config_file_path = os.path.join(self.temp_dir, 'test_fwsimple.cfg')
        config_content = config_content.replace('%%RULESETS_DIR%%', self.rules_dir)

        with open(config_file_path, 'w') as f:
            f.write(config_content)

        for file_name, content in rules_files.items():
            with open(os.path.join(self.rules_dir, file_name), 'w') as f:
                f.write(content)

        old_stdout = sys.stdout
        sys.stdout = captured_stdout = io.StringIO()

        try:
            firewall_args = {'configfile': config_file_path, 'dry_run': True}
            firewall_args.update(self._get_engine_specific_firewall_args())
            fw = Firewall(**firewall_args)
            fw.commit()
        finally:
            sys.stdout = old_stdout

        output = captured_stdout.getvalue().strip()
        if not output:
            return []

        # Process output using a potentially overridden method
        processed_output = self._process_dry_run_output(output.splitlines())
        return processed_output

    def _normalize_command(self, cmd_str: str) -> str:
        """
        Abstract method for subclasses to implement command normalization.
        """
        raise NotImplementedError("Subclasses must implement _normalize_command")

    def assert_commands_equal(self, actual_commands: List[str], expected_commands: List[str]):
        actual_normalized = [self._normalize_command(cmd) for cmd in actual_commands]
        # Normalize expected commands as well, as they might be written with prefixes for readability in tests
        expected_normalized = [self._normalize_command(cmd) for cmd in expected_commands]

        self.assertEqual(len(actual_normalized), len(expected_normalized),
                         "Number of commands differ.\nActual: {0}\nExpected: {1}".format(actual_normalized, expected_normalized))

        for i, actual_cmd in enumerate(actual_normalized):
            self.assertEqual(actual_cmd, expected_normalized[i],
                             "Command {0} differs.\nActual:   {1}\nExpected: {2}\n\nFull Actual:\n{3}\n\nFull Expected:\n{4}".format(i+1, actual_cmd, expected_normalized[i], actual_normalized, expected_normalized))
