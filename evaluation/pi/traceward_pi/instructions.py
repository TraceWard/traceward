"""Initial instruction capture for the pinned Pi CLI, independent of its hooks."""
from pathlib import PurePosixPath
import sys
from traceward.instructions import bind_instruction, instruction_arguments


def pi_instruction(args):
    positions, options = instruction_arguments(args,
        values={'--provider', '--model', '--api-key', '--system-prompt', '--append-system-prompt',
                '--mode', '--session', '--session-dir', '--name', '-n', '--models',
                '--tools', '-t', '--exclude-tools', '-xt', '--thinking',
                '--extension', '-e', '--skill', '--prompt-template', '--theme', '--use-theme', '--tui-mode'},
        switches={'--print', '-p', '--no-session', '--no-tools', '-nt', '--no-builtin-tools', '-nbt',
                  '--no-extensions', '-ne', '--no-skills', '-ns', '--no-prompt-templates', '-np',
                  '--no-themes', '--no-context-files', '-nc', '--verbose', '--approve', '-a',
                  '--no-approve', '-na', '--offline'},
        commands=set(),
        forbidden={'--continue', '-c', '--resume', '-r', '--fork', '--session-id', '--export',
                   '--list-models', '--help', '-h', '--version', '-v'}, attached_values=False)
    if options.get('--mode') == 'rpc':
        raise ValueError('Pi RPC mode has no launch-time initial instruction; use a fresh text/json session')
    if '--session' in options:
        path = PurePosixPath(options['--session'])
        if not path.is_relative_to('/pi-home') or '..' in path.parts:
            raise ValueError('Pi --session must name a new file inside the fresh /pi-home directory')
    if any(args[index].startswith('@') for index in positions):
        raise ValueError('Pi @file initial prompts are unsupported; provide the initial instruction as text')
    if args and args[0] in {'install', 'remove', 'uninstall', 'update', 'list', 'config', 'auth'}:
        raise ValueError('Pi management commands do not provide an initial agent instruction')
    if not positions and sys.stdin.isatty() and not any(flag in options for flag in ('--print', '-p', '--mode')):
        return None, list(args)  # Pi's input hook supplies the first submitted chat.
    goal, forwarded = bind_instruction(args, positions, agent='pi')
    if goal.startswith('@'):
        raise ValueError('Pi @file initial prompts are unsupported; provide the initial instruction as text')
    return goal, forwarded
