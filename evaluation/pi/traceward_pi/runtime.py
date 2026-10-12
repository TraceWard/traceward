"""Pi-specific setup for the optional evaluation harness."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import traceward
from traceward.runtime import AgentSpec, ManagedRuntime, RUNNER_IMAGE, checked, ensure_image
from .transport import PI_IMAGE, PI_MODEL, PI_VERSION, HostModelRelay, model_config, private_json


def ensure_pi_image():
    if subprocess.run(['docker','image','inspect',PI_IMAGE],capture_output=True).returncode:
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
            checked(['docker','build','-t',PI_IMAGE,'-f',str(context/'evaluation/pi/image/Pi.Dockerfile'),str(context)])
    return ensure_image(PI_IMAGE)


class PiRuntime(ManagedRuntime):
    def __init__(self, run_dir, run_id, args, *, pi_model=None, pi_url=None,
                 pi_seed=42, pi_max_calls=24, **kwargs):
        self.relay=None
        if os.environ.get('TRACEWARD_MANAGED_RUNNER')=='1':
            raise ValueError('Pi lab requires the managed Docker boundary')
        home=run_dir/'pi-home';home.mkdir(mode=0o700)
        config=home/'.pi/agent';config.mkdir(parents=True,mode=0o700)
        private_json(config/'models.json',model_config(pi_model or PI_MODEL,pi_seed))
        private_json(config/'settings.json',{'quietStartup':True,'enableSkillCommands':False})
        spec=AgentSpec('pi',home,'/pi-home',
            ['pi','--offline','--no-extensions','--extension','/opt/traceward-hooks/traceward_pi/extension.mjs',
             '--provider','traceward-local','--model',pi_model or PI_MODEL,*args],PI_IMAGE,
            env={'PI_CODING_AGENT_DIR':'/pi-home/.pi/agent','PI_OFFLINE':'1'},
            metadata={'pi_version':PI_VERSION,'actor_model':pi_model or PI_MODEL,
                      'network':'Docker none; loopback fixture and fixed host model relay'},
            ensure_default_image=ensure_pi_image,network_none=True,embedded_supported=False,
            supervisor_module='traceward_pi.runner',transport_endpoints=('127.0.0.1:8801',),
            hook_setup_hint='check the Pi observer extension',permission_log=run_dir/'runtime-permissions.jsonl',
            request_extra={'lab_canary_sha256':os.environ.get('TRACEWARD_LAB_CANARY_SHA256'),
                           'lab_permission_decision':os.environ.get('TRACEWARD_LAB_PERMISSION_DECISION')})
        super().__init__(run_dir,run_id,args,agent_spec=spec,**kwargs)
        self.relay=HostModelRelay(run_dir,pi_model or PI_MODEL,
            pi_url or 'http://127.0.0.1:1234/v1/chat/completions',max_requests=pi_max_calls)

    def cleanup(self):
        try: super().cleanup()
        finally:
            if self.relay: self.relay.close()
