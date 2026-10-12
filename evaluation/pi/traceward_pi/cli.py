"""Explicit CLI for the optional Pi lab, with legacy core-command bridges."""
import sys
from traceward import cli as core
from traceward.config import load_observer_env
from .runtime import PiRuntime


def _options(args):
    remaining=[];options={};index=0
    while index<len(args) and args[index]!='pi':
        flag=args[index]
        if not flag.startswith('--'): raise ValueError('--pi-* options require the pi agent')
        width=1 if flag=='--defer-judge' else 2
        if index+width>len(args): raise ValueError('Missing value for '+flag)
        if flag.startswith('--pi-'):
            key=flag[2:].replace('-','_')
            if key not in {'pi_model','pi_url','pi_seed','pi_max_calls'}: raise ValueError('Unknown Pi option '+flag)
            options[key]=int(args[index+1]) if key in {'pi_seed','pi_max_calls'} else args[index+1]
        else: remaining.extend(args[index:index+width])
        index+=width
    if index>=len(args): raise ValueError('--pi-* options require the pi agent')
    if not 1<=options.get('pi_max_calls',24)<=100: raise ValueError('--pi-max-calls must be between 1 and 100')
    return [*remaining,'codex',*args[index+1:]],options


def parse_run(args):
    remaining,options=_options(args)
    parsed=list(core._parse_run(remaining));parsed[-1].update(agent='pi',**options)
    return tuple(parsed)


def run(args):
    load_observer_env(extra_keys={'TRACEWARD_PI_TOKEN'})
    remaining,options=_options(args)
    return core.run(remaining,runtime_factory=PiRuntime,runtime_options=options,agent_name='pi')


def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    try:
        load_observer_env(extra_keys={'TRACEWARD_PI_TOKEN'})
        if args and args[0]=='eval':
            from .evaluate import main as evaluate
            return evaluate(args[1:])
        if args and args[0]=='run': return run(args[1:])
        print('usage: traceward-pi eval [EVALUATION FLAGS...]\n       traceward-pi run [TRACEWARD/PI OPTIONS...] pi [PI FLAGS...]')
        return 0 if not args or args[0] in {'-h','--help'} else 2
    except (OSError,ValueError,RuntimeError) as exc:
        print('traceward-pi: '+str(exc),file=sys.stderr);return 2


if __name__=='__main__': raise SystemExit(main())
