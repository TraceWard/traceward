"""Explicit operator scope overrides the default initial-instruction goal."""
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceward.cli import _parse_run, run


class InstructionTests(unittest.TestCase):
    def setUp(self):
        self.stdin = patch('sys.stdin', io.StringIO(''))
        self.stdin.start()
        self.addCleanup(self.stdin.stop)

    def test_codex_options_are_not_mistaken_for_the_instruction(self):
        args = ['--sandbox', 'workspace-write', '-cmodel="a different model"',
                'exec', '--output-last-message', '/tmp/result', '--color=never',
                '-mactor', '  Fix tests.\nDo not edit private files.  ']
        parsed = _parse_run(['codex', *args])
        self.assertEqual(parsed[0], args[-1])
        self.assertEqual(parsed[2], args)

    def test_literal_prompt_can_look_like_an_option_or_command(self):
        for text in ['--goal is a string in this task', 'resume']:
            parsed = _parse_run(['codex', 'exec', '--', text])
            self.assertEqual(parsed[0], text)
            self.assertEqual(parsed[2], ['exec', '--', text])

    def test_interactive_instruction_is_asked_once_and_sent_to_agent(self):
        with patch('sys.stdin.isatty', return_value=True), \
             patch('builtins.input', return_value='- Fix the arithmetic') as ask:
            parsed = _parse_run(['codex', '--sandbox', 'workspace-write'])
        ask.assert_called_once_with('Initial instruction: ')
        self.assertEqual(parsed[0], '- Fix the arithmetic')
        self.assertEqual(parsed[2], ['--sandbox', 'workspace-write', '--', parsed[0]])

    def test_stdin_instruction_is_frozen_and_forwarded_without_trimming(self):
        for args in [[], ['exec'], ['exec', '-']]:
            with self.subTest(args=args), patch('sys.stdin', io.StringIO('Fix arithmetic\n')):
                parsed = _parse_run(['codex', *args])
            self.assertEqual(parsed[0], 'Fix arithmetic\n')
            self.assertEqual(parsed[2][-1], parsed[0])
            self.assertNotIn('-', parsed[2])
        with patch('sys.stdin', io.StringIO('-- Fix arithmetic')):
            parsed = _parse_run(['codex', 'exec', '-'])
        self.assertEqual(parsed[2], ['exec', '--', '-- Fix arithmetic'])

    def test_no_instruction_or_mixed_input_does_not_launch_runtime(self):
        for args, data in [(['codex', 'exec'], ''), (['codex', 'exec', 'Fix tests'], 'other goal')]:
            with self.subTest(args=args), patch('sys.stdin', io.StringIO(data)), \
                 patch('traceward.cli.ManagedRuntime') as runtime:
                with self.assertRaises(ValueError):
                    run(args)
                runtime.assert_not_called()

    def test_explicit_goal_preserves_the_agent_prompt_and_stdin(self):
        stream = io.StringIO('Additional agent input')
        args = ['exec', 'Start by reading README.md']
        with patch('sys.stdin', stream):
            parsed = _parse_run(['--goal', 'Repair the entire billing workflow', 'codex', *args])
        self.assertEqual(parsed[0], 'Repair the entire billing workflow')
        self.assertEqual(parsed[2], args)
        self.assertEqual(stream.tell(), 0)

    def test_explicit_goal_does_not_require_a_launch_instruction(self):
        for args in [[], ['resume', '--last']]:
            with self.subTest(args=args), patch('builtins.input') as ask:
                parsed = _parse_run(['--goal', 'Maintain the project', 'codex', *args])
            ask.assert_not_called()
            self.assertEqual(parsed[0], 'Maintain the project')
            self.assertEqual(parsed[2], args)

    def test_goal_file_is_read_once_and_keeps_multiline_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'session goal.md'
            goal = 'Repair the project.\nPreserve the public API.\n'
            file.write_text(goal)
            parsed = _parse_run(['--goal-file', str(file), 'codex', 'Start with the tests'])
            file.write_text('A later edit must not change this run')
        self.assertEqual(parsed[0], goal)
        self.assertEqual(parsed[2], ['Start with the tests'])

    def test_invalid_goal_overrides_fail_without_inference_or_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / 'empty.md'
            empty.write_text(' \n')
            cases = [(['--goal', '', 'codex'], ValueError, 'cannot be empty'),
                     (['--goal', '  ', 'codex'], ValueError, 'cannot be empty'),
                     (['--goal-file', str(empty), 'codex'], ValueError, 'cannot be empty'),
                     (['--goal-file', str(empty / 'missing'), 'codex'], OSError, ''),
                     (['--goal', 'scope', '--goal-file', str(empty), 'codex'], ValueError, 'not both')]
            for args, error, message in cases:
                with self.subTest(args=args), patch('traceward.cli.ManagedRuntime') as runtime, \
                     self.assertRaisesRegex(error, message):
                    run(args)
                runtime.assert_not_called()

    def test_ambiguous_modes_without_an_explicit_goal_fail_before_launch(self):
        cases = [(['codex', 'resume', '--last'], 'fresh initial instruction'),
                 (['codex', 'exec', 'resume', 'session-id', 'Fix tests'], 'fresh initial instruction'),
                 (['codex', '--unknown-option', 'not the goal', 'Fix tests'], 'instruction adapter'),
                 (['codex', 'exec', '--model'], 'missing value'),
                 (['codex', 'exec', '  '], 'cannot be empty'),
                 (['codex', 'exec', 'one', 'two'], 'single argument')]
        for args, message in cases:
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, message):
                _parse_run(args)


if __name__ == '__main__':
    unittest.main()
