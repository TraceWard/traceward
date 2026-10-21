"""Pi-specific setup for the optional evaluation harness."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import traceward
from traceward.runtime import AgentSpec, ManagedRuntime, RUNNER_IMAGE, checked, ensure_image
from .transport import PI_IMAGE, PI_MODEL, PI_VERSION, HostModelRelay, model_config, private_json

INSPECTION_IMAGE = 'traceward-pi:0.85.1-inspect1'


def _source_signature():
    files = [*Path(traceward.__file__).parent.glob('*.py'), *Path(__file__).parent.glob('*.py'),
             *Path(__file__).parent.glob('*.mjs')]
    return hashlib.sha256(b''.join(p.name.encode() + p.read_bytes() for p in sorted(files))).hexdigest()


def ensure_pi_image():
    signature = _source_signature()
    probe = subprocess.run(['docker','image','inspect',PI_IMAGE],capture_output=True,text=True)
    labels = json.loads(probe.stdout)[0].get('Config',{}).get('Labels') or {} if probe.returncode == 0 else {}
    if probe.returncode or labels.get('ai.traceward.source-sha') != signature:
        ensure_image(RUNNER_IMAGE)
        package=Path(__file__).resolve().parent
        recipe=package/'image/Pi.Dockerfile'
        if not recipe.exists(): recipe=package.parent/'image/Pi.Dockerfile'
        with tempfile.TemporaryDirectory(prefix='traceward-pi-build-') as directory:
            context=Path(directory)
            ignore=shutil.ignore_patterns('__pycache__')
            shutil.copytree(Path(traceward.__file__).parent,context/'src/traceward',ignore=ignore)
            shutil.copytree(package,context/'evaluation/pi/traceward_pi',ignore=ignore)
            (context/'evaluation/pi/image').mkdir(parents=True)
            shutil.copyfile(recipe,context/'evaluation/pi/image/Pi.Dockerfile')
            checked(['docker','build','--label','ai.traceward.source-sha='+signature,
                     '-t',PI_IMAGE,'-f',str(context/'evaluation/pi/image/Pi.Dockerfile'),str(context)])
    return ensure_image(PI_IMAGE)


def ensure_inspection_image():
    base = ensure_pi_image()
    recipe = Path(__file__).parent / 'image/Inspection.Dockerfile'
    if not recipe.exists(): recipe = Path(__file__).parent.parent / 'image/Inspection.Dockerfile'
    signature = hashlib.sha256((base['Id'] + recipe.read_text()).encode()).hexdigest()
    probe = subprocess.run(['docker','image','inspect',INSPECTION_IMAGE],capture_output=True,text=True)
    labels = json.loads(probe.stdout)[0].get('Config',{}).get('Labels') or {} if probe.returncode == 0 else {}
    if probe.returncode or labels.get('ai.traceward.inspection-sha') != signature:
        checked(['docker','build','--label','ai.traceward.inspection-sha='+signature,
                 '--build-arg','PI_BASE_IMAGE='+PI_IMAGE,'-t',INSPECTION_IMAGE,'-f',str(recipe),str(recipe.parent)])
    return ensure_image(INSPECTION_IMAGE)


class PiRuntime(ManagedRuntime):
    def __init__(self, run_dir, run_id, args, *, pi_model=None, pi_url=None,
                 pi_seed=42, pi_max_calls=24, pi_network='none', pi_inspect_https=False,
                 capture_initial_goal=False, **kwargs):
        self.relay=None
        if pi_network not in {'none','bridge'}:
            raise ValueError('--pi-network must be none or bridge')
        if pi_inspect_https and pi_network != 'bridge':
            raise ValueError('--pi-inspect-https requires --pi-network bridge')
        if os.environ.get('TRACEWARD_MANAGED_RUNNER')=='1':
            raise ValueError('Pi lab requires the managed Docker boundary')
        home=run_dir/'pi-home';home.mkdir(mode=0o700)
        config=home/'.pi/agent';config.mkdir(parents=True,mode=0o700)
        private_json(config/'models.json',model_config(pi_model or PI_MODEL,pi_seed))
        private_json(config/'settings.json',{'quietStartup':True,'enableSkillCommands':False})
        spec=AgentSpec('pi',home,'/pi-home',
            ['pi','--offline','--no-extensions','--extension','/opt/traceward-hooks/traceward_pi/extension.mjs',
             '--provider','traceward-local','--model',pi_model or PI_MODEL,*args],INSPECTION_IMAGE if pi_inspect_https else PI_IMAGE,
            env={'PI_CODING_AGENT_DIR':'/pi-home/.pi/agent','PI_OFFLINE':'1',
                 'TRACEWARD_CAPTURE_INITIAL_GOAL': '1' if capture_initial_goal else '0'},
            metadata={'pi_version':PI_VERSION,'actor_model':pi_model or PI_MODEL,
                      'pi_network':pi_network,
                      'https_inspection': pi_inspect_https,
                      'network':('Docker none; loopback fixture and fixed host model relay' if pi_network=='none'
                                 else 'Docker bridge; outbound access and fixed host model relay')},
            ensure_default_image=ensure_inspection_image if pi_inspect_https else ensure_pi_image,
            network_none=pi_network=='none',embedded_supported=False,
            supervisor_module='traceward_pi.runner',transport_endpoints=('127.0.0.1:8801',),
            hook_setup_hint='check the Pi observer extension',permission_log=run_dir/'runtime-permissions.jsonl',
            request_extra={'lab_canary_sha256':os.environ.get('TRACEWARD_LAB_CANARY_SHA256'),
                           'lab_permission_decision':os.environ.get('TRACEWARD_LAB_PERMISSION_DECISION'),
                           'inspect_https': pi_inspect_https})
        super().__init__(run_dir,run_id,args,agent_spec=spec,**kwargs)
        if pi_inspect_https:
            self.gaps.append('HTTPS inspection covers proxy-using HTTP(S) clients; direct traffic, QUIC, private trust stores and pinned certificates may bypass or fail inspection')
        self.relay=HostModelRelay(run_dir,pi_model or PI_MODEL,
            pi_url or 'http://127.0.0.1:1234/v1/chat/completions',max_requests=pi_max_calls)

    def cleanup(self):
        try: super().cleanup()
        finally:
            if self.relay: self.relay.close()
