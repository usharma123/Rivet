"""Guard against silently weakened workflows while dependency updates evolve them."""
from pathlib import Path
import re
import json
import os
import subprocess
import sys
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowContract(unittest.TestCase):
    def test_third_party_actions_are_immutable(self):
        for path in (ROOT / '.github').rglob('*.yml'):
            for action in re.findall(r'uses:\s*([^\s#]+)', path.read_text()):
                if not action.startswith('./'):
                    self.assertRegex(action, r'@([a-f0-9]{40})$', str(path))

    def test_no_product_execution_in_privileged_pr_context(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            source = path.read_text()
            if 'pull_request_target:' in source:
                self.assertNotIn('actions/checkout', source)
                self.assertNotRegex(source, r'\brun:')

    def test_required_gate_covers_every_check(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text()
        # Extract only the jobs block, excluding top-level event/default mappings.
        source = source.split('\njobs:\n', 1)[1]
        jobs = set(re.findall(r'^  ([a-z][a-z0-9-]+):\n', source, re.M))
        gate = source.split('\n  required:', 1)[1]
        needs = re.search(r'needs: \[([^\]]+)\]', gate).group(1)
        self.assertEqual(set(x.strip() for x in needs.split(',')), jobs - {'required'})
        self.assertIn('if: ${{ !cancelled() }}', gate)
        self.assertIn("job['result'] != 'success'", gate)

    def test_required_gate_rejects_every_unsuccessful_dependency(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text()
        gate = source.split('\n  required:', 1)[1]
        script = textwrap.dedent(gate.split("python3 - <<'PYCODE'\n", 1)[1]
                                 .split('          PYCODE', 1)[0])
        for result in ('success', 'failure', 'cancelled', 'skipped'):
            with self.subTest(result=result):
                env = dict(os.environ, RESULTS=json.dumps({
                    'workspace': {'result': 'success'},
                    'product': {'result': result},
                }))
                run = subprocess.run([sys.executable, '-c', script], env=env,
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode == 0, result == 'success',
                                 run.stdout + run.stderr)

    def test_local_linux_image_uses_the_registry_toolchain(self):
        version = re.search(r'^go (\S+)$', (ROOT / 'registry/go.mod').read_text(), re.M).group(1)
        docker_version = re.search(r'^ARG GO_VERSION=(\S+)$',
                                  (ROOT / 'tools/e2e/Dockerfile.linux').read_text(), re.M).group(1)
        self.assertEqual(docker_version, version)


if __name__ == '__main__':
    unittest.main()
