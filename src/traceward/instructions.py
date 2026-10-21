"""Bind a fresh agent invocation to its initial operator instruction."""
from __future__ import annotations

import sys


def instruction_arguments(args: list[str], *, values: set[str], switches: set[str],
                          commands: set[str], forbidden: set[str],
                          attached_values: bool = True) -> tuple[list[int], dict[str, str]]:
    """Locate text operands without mistaking option values for the goal.

    Unknown flags fail explicitly: guessing their arity could authorise a model
    name, path or extension option instead of the user's instruction.
    """
    positions, options = [], {}
    index, literal = 0, False
    while index < len(args):
        arg = args[index]
        if not literal and arg == '--':
            literal = True
        elif not literal and arg in forbidden:
            raise ValueError(f'{arg} cannot provide a fresh initial instruction; start a new agent session')
        elif not literal and arg in commands and not positions:
            if options.get('command'):
                raise ValueError('nested agent commands are not supported for initial-instruction capture')
            options['command'] = arg
        elif not literal and arg.startswith('-') and arg != '-':
            flag, separator, value = arg.partition('=')
            # Codex/clap supports attached short-option values, e.g. -mMODEL.
            if attached_values and not arg.startswith('--') and arg not in values | switches and arg[:2] in values:
                flag, value, separator = arg[:2], arg[2:], '='
            if flag in forbidden:
                raise ValueError(f'{flag} cannot provide a fresh initial instruction; start a new agent session')
            if flag in values and (attached_values or not separator):
                if not separator:
                    index += 1
                    if index >= len(args):
                        raise ValueError(f'missing value for {flag}')
                    value = args[index]
                options[flag] = value
            elif flag in switches and not separator:
                options[flag] = 'true'
            else:
                raise ValueError(f'cannot capture the initial instruction with agent option {flag}; '
                                 'this option is not supported by the instruction adapter')
        else:
            positions.append(index)
        index += 1
    return positions, options


def bind_instruction(args: list[str], positions: list[int], *, agent: str) -> tuple[str, list[str]]:
    """Freeze text supplied by the operator and pass exactly that text onward.

    Interactive prompt-less starts ask once here. Stdin-only starts are converted
    to a text operand so the observer and guest receive the same instruction.
    Mixed stdin/argv input is rejected rather than guessing what is authority.
    """
    forwarded = list(args)
    goal = args[positions[0]] if positions else None
    piped = None
    if not sys.stdin.isatty():
        piped = sys.stdin.read(1024 * 1024 + 1)
        if len(piped) > 1024 * 1024:
            raise ValueError('initial instruction exceeds 1 MiB')
    if goal == '-' and agent == 'codex':
        goal = None
    elif goal is not None and piped:
        raise ValueError('mixed prompt and piped input is unsupported; supply one initial text instruction')
    if goal is None:
        if piped:
            goal = piped
        elif sys.stdin.isatty():
            goal = input('Initial instruction: ')
        if goal is None:
            raise ValueError('an initial user instruction is required; pass it to the agent or pipe it on stdin')
        if positions:
            forwarded[positions[0]] = goal
            if '--' not in forwarded[:positions[0]]:
                forwarded.insert(positions[0], '--')
        else:
            # A delimiter prevents an instruction beginning with '-' or a command
            # name from being reinterpreted by the agent CLI.
            if '--' not in forwarded:
                forwarded.append('--')
            forwarded.append(goal)
    if not goal.strip():
        raise ValueError('initial instruction cannot be empty')
    return goal, forwarded


def codex_instruction(args: list[str]) -> tuple[str, list[str]]:
    positions, _ = instruction_arguments(args,
        values={'-c', '--config', '--enable', '--disable', '-m', '--model',
                '--local-provider', '-p', '--profile', '-s', '--sandbox',
                '-C', '--cd', '--add-dir', '-a', '--ask-for-approval',
                '--thread-source', '--output-schema', '--color', '-o', '--output-last-message',
                '-i', '--image'},
        switches={'--strict-config', '--oss', '--approve-for-me', '--full-auto',
                  '--dangerously-bypass-approvals-and-sandbox', '--search', '--no-alt-screen',
                  '--no-daemon', '--worktree', '--skip-git-repo-check', '--ephemeral',
                  '--ignore-user-config', '--ignore-rules', '--json'},
        commands={'exec', 'e'},
        forbidden={'resume', 'fork', 'review', 'login', 'logout', 'mcp', 'plugin', 'app-server',
                   'remote-control', 'app', 'completion', 'update', 'doctor', 'sandbox', 'debug',
                   'apply', 'a', 'queue', 'archive', 'delete', 'migrate-rollouts', 'unarchive',
                   'cloud', 'exec-server', 'features', 'agents', 'help', '--remote',
                   '--remote-auth-token-env', '--help', '-h', '--version', '-V'})
    if len(positions) > 1:
        raise ValueError('Codex requires one initial text instruction; quote it as a single argument')
    return bind_instruction(args, positions, agent='codex')
