import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runsc_query', Path(__file__).resolve().parents[1] / 'deploy/runsc-query.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class RunscQueryBoundary(unittest.TestCase):
    def test_only_read_queries_for_full_container_ids(self):
        identifier = 'a' * 64
        for command in (['ps', '-format=json'], ['trace', 'list']):
            self.assertEqual(helper.query_args([helper.ROOT, *command, identifier]),
                             [helper.RUNSC, '--allow-flag-override', helper.ROOT, *command, identifier])
        self.assertEqual(helper.query_args(['--version']), [helper.RUNSC, '--version'])

    def test_rejects_paths_flags_and_mutations(self):
        identifier = 'a' * 64
        for args in (
            [], ['--version', '--debug'], ['--root=/tmp', 'ps', '-format=json', identifier],
            [helper.ROOT, 'trace', 'create', identifier],
            [helper.ROOT, 'ps', '-format=json', '../sandbox'],
            [helper.ROOT, 'ps', '-format=json', 'a' * 12],
            [helper.ROOT, 'ps', '-format=json', identifier, '--debug'],
            [helper.ROOT, 'run', '-format=json', identifier],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                helper.query_args(args)
