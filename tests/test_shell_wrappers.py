"""Opt-in checks of the operator's two installed zsh wrappers, without launch."""
import os
import re
import shlex
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.environ.get('TRACEWARD_TEST_ZSHRC'),'installed zsh wrappers not selected')
class ShellWrappers(unittest.TestCase):
    def invoke(self,name,args,environment=None):
        source=Path(os.environ['TRACEWARD_TEST_ZSHRC']).read_text()
        match=re.search(r'^'+name+r'\(\) \{.*?^\}',source,re.M|re.S)
        self.assertIsNotNone(match)
        function=re.sub(r'\S*/\.venv/bin/python\b','_record',match[0])
        script='_record() { printf "%s\\0" "$@"; }\n'+function+'\n'+name+' '+shlex.join(args)
        result=subprocess.run(['zsh','-f','-c',script],env={**os.environ,**(environment or {})},capture_output=True)
        return result,[x.decode() for x in result.stdout.split(b'\0') if x]

    def test_url_selector_and_native_arguments(self):
        for name,native in (('tpi','pi'),('tcodex','codex')):
            with self.subTest(name=name):
                result,args=self.invoke(name,['--traceward-url','http://override:8765','--agent-id','test-id','--print','two words'],{'TRACEWARD_URL':'http://environment:8765'})
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('test-id',args)
                positions=[n for n,value in enumerate(args) if value=='--traceward-url']
                self.assertEqual(args[positions[-1]+1],'http://override:8765')
                self.assertEqual(args[-2:],['--print','two words'])
                self.assertIn(native,args)
                self.assertFalse(any(a.startswith('--judge-') for a in args))
                if name=='tcodex':
                    self.assertIn('workspace-write',args);self.assertIn('sandbox_workspace_write.network_access=true',args)
                else:
                    for option in ('--pi-model','--pi-url','--pi-network','--pi-inspect-https','--guest-image'):self.assertIn(option,args)

    def test_unattributed_default_and_backend_judge_guidance(self):
        for name in ('tpi','tcodex'):
            result,args=self.invoke(name,['--print','inspect only'],{'TRACEWARD_URL':'http://environment:8765'})
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('http://environment:8765',args)
            self.assertNotIn('--agent-id',args);self.assertNotIn('--agent-slug',args)
            result,_=self.invoke(name,['--judge-model','old-local-setting'])
            self.assertEqual(result.returncode,2)
            self.assertIn(b'backend',result.stderr)
