"""Provider routing, credential isolation and shared judgement validation."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from io import BytesIO

from traceward.cli import _parse_run
from traceward.config import load_observer_env
from traceward.judges import judge, OPENROUTER_URL
from traceward.privacy import redact
from tests.test_judges import packet, response

class ProviderAdapterTests(unittest.TestCase):
    def invoke(self,env,*,result=None,**options):
        calls=[]
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps(result or response(model=env.get('TRACEWARD_JUDGE_MODEL','qwen/qwen3.8-27b'))).encode()[:n]
        def post(request,**kwargs):calls.append(request);return Reply()
        with patch.dict(os.environ,env,clear=True),patch('traceward.judges.urlopen',post), \
             patch('traceward.openrouter.canonical_model',return_value='vendor/model-dated'):
            answer=judge(packet(),**options)
        return answer,calls

    def test_openrouter_uses_fixed_endpoint_model_and_only_its_credential(self):
        env=dict(TRACEWARD_JUDGE_PROVIDER='openrouter',TRACEWARD_JUDGE_URL='http://localhost:1234/v1',
                 TRACEWARD_JUDGE_MODEL='vendor/synthetic-model',OPENROUTER_KEY='synthetic-router-secret',
                 LMSTUDIO_API_KEY='synthetic-local-secret',TRACEWARD_JUDGE_TOKEN='synthetic-legacy-secret')
        answer,calls=self.invoke(env)
        self.assertEqual(answer['status'],'assessed')
        self.assertEqual(answer['provider'],'openrouter')
        self.assertEqual(answer['requested_model'],'vendor/synthetic-model')
        self.assertEqual(calls[0].full_url,OPENROUTER_URL)
        self.assertEqual(calls[0].get_header('Authorization'),'Bearer synthetic-router-secret')
        body=json.loads(calls[0].data)
        self.assertEqual(body['model'],'vendor/synthetic-model')
        self.assertEqual(body['provider'],{'require_parameters':True})
        self.assertEqual(body['reasoning'],{'enabled':True})
        self.assertTrue(body['response_format']['json_schema']['strict'])
        self.assertNotIn('seed',body);self.assertNotIn('reasoning_effort',body);self.assertNotIn('temperature',body)
        for key in ('synthetic-router-secret','synthetic-local-secret','synthetic-legacy-secret'):
            self.assertNotIn(key,json.dumps(answer));self.assertNotIn(key,json.dumps(body))

    def test_lmstudio_uses_local_settings_optional_key_and_legacy_alias(self):
        for credentials,expected in [({},None),({'LMSTUDIO_API_KEY':'local-key'},'local-key'),
                ({'TRACEWARD_JUDGE_TOKEN':'legacy-key'},'legacy-key'),
                ({'LMSTUDIO_API_KEY':'local-key','TRACEWARD_JUDGE_TOKEN':'legacy-key'},'local-key')]:
            with self.subTest(credentials=tuple(credentials)):
                answer,calls=self.invoke(dict(TRACEWARD_JUDGE_PROVIDER='lmstudio',
                    TRACEWARD_JUDGE_URL='http://localhost:1234/api/v1',TRACEWARD_JUDGE_MODEL='local/model',
                    OPENROUTER_KEY='unused-router-key',**credentials))
                self.assertEqual(answer['status'],'assessed')
                self.assertEqual(calls[0].full_url,'http://localhost:1234/v1/chat/completions')
                self.assertEqual(calls[0].get_header('Authorization'),'Bearer '+expected if expected else None)
                self.assertEqual(json.loads(calls[0].data)['reasoning_effort'],'none')
                self.assertNotIn('provider',json.loads(calls[0].data))
                self.assertNotIn('unused-router-key',json.dumps(answer))

    def test_missing_openrouter_settings_never_fall_back_to_local_defaults(self):
        for env,reason in [(dict(TRACEWARD_JUDGE_MODEL='vendor/model'),'missing_openrouter_key'),
                           (dict(OPENROUTER_KEY='secret'),'missing_judge_model')]:
            answer,calls=self.invoke(dict(TRACEWARD_JUDGE_PROVIDER='openrouter',**env))
            self.assertFalse(calls);self.assertEqual(answer['reason'],reason)
        answer,calls=self.invoke(dict(TRACEWARD_JUDGE_PROVIDER='openrouter',TRACEWARD_JUDGE_MODEL='vendor/model',
            LMSTUDIO_API_KEY='local-only',TRACEWARD_JUDGE_TOKEN='old-only'))
        self.assertEqual(answer['reason'],'missing_openrouter_key');self.assertFalse(calls)

    def test_explicit_options_override_provider_and_model_environment(self):
        answer,calls=self.invoke(dict(TRACEWARD_JUDGE_PROVIDER='lmstudio',TRACEWARD_JUDGE_MODEL='local/model',
            OPENROUTER_KEY='router-key'),provider='openrouter',model='vendor/selected',
            result=response(model='vendor/selected'))
        self.assertEqual(answer['provider'],'openrouter')
        self.assertEqual(json.loads(calls[0].data)['model'],'vendor/selected')
        with patch.dict(os.environ,{'TRACEWARD_JUDGE_PROVIDER':'openrouter'},clear=True):
            parsed=_parse_run(['--goal','Read fixtures','codex'])
            self.assertIsNotNone(parsed)
            _parse_run(['--goal','Read fixtures','--judge-provider','lmstudio','codex'])
        with patch.dict(os.environ,{'TRACEWARD_JUDGE_PROVIDER':'unknown'},clear=True):
            with self.assertRaisesRegex(ValueError,'lmstudio or openrouter'):_parse_run(['--goal','Read fixtures','codex'])

    def test_cloud_response_is_still_identity_completion_and_citation_checked(self):
        env=dict(TRACEWARD_JUDGE_PROVIDER='openrouter',TRACEWARD_JUDGE_MODEL='vendor/model',OPENROUTER_KEY='router-key')
        answer,_=self.invoke(env,result=response(model='other/model'))
        self.assertEqual(answer['reason'],'returned_model_mismatch')
        wrong=response(model='vendor/model');wrong['choices'][0]['finish_reason']='length'
        answer,_=self.invoke(env,result=wrong);self.assertEqual(answer['reason'],'invalid_structured_answer')
        wrong=response(model='vendor/model');wrong['choices'][0]['message']['content']=json.dumps(
            dict(disposition='review_required',rationale='Synthetic',evidence_ids=['invented']))
        answer,_=self.invoke(env,result=wrong);self.assertEqual(answer['reason'],'invalid_structured_answer')

    def test_response_and_http_errors_cannot_persist_the_active_key(self):
        env=dict(TRACEWARD_JUDGE_PROVIDER='openrouter',TRACEWARD_JUDGE_MODEL='vendor/model',OPENROUTER_KEY='synthetic-echoed-key')
        answer,_=self.invoke(env,result={'error':{'code':429,'message':'synthetic-echoed-key'}})
        self.assertEqual(answer['reason'],'provider_error');self.assertEqual(answer['error_code'],429)
        self.assertNotIn('synthetic-echoed-key',json.dumps(answer))
        result=response(model='vendor/model')
        parsed=json.loads(result['choices'][0]['message']['content']);parsed['rationale']='Synthetic synthetic-echoed-key'
        result['choices'][0]['message']['content']=json.dumps(parsed)
        answer,_=self.invoke(env,result=result);self.assertNotIn('synthetic-echoed-key',json.dumps(answer))
        with patch.dict(os.environ,env,clear=True),patch('traceward.judges.urlopen',side_effect=
            HTTPError(OPENROUTER_URL,401,'Unauthorized',{},BytesIO(b'synthetic-echoed-key'))):
            answer=judge(packet())
        self.assertEqual(answer['http_status'],401);self.assertNotIn('synthetic-echoed-key',json.dumps(answer))

    def test_env_loader_accepts_both_credentials_and_preserves_process_precedence(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'LMSTUDIO_API_KEY':'process-local'},clear=True):
            path=Path(d)/'settings.env'
            path.write_text('OPENROUTER_KEY=file-router\nLMSTUDIO_API_KEY=file-local\nUNRELATED_SECRET=ignored\n')
            load_observer_env(path)
            self.assertEqual(os.environ['OPENROUTER_KEY'],'file-router')
            self.assertEqual(os.environ['LMSTUDIO_API_KEY'],'process-local')
            self.assertNotIn('UNRELATED_SECRET',os.environ)
        self.assertEqual(redact('OPENROUTER_KEY=synthetic-plain-key'),'OPENROUTER_KEY=[REDACTED]')

    def test_canonical_identity_requires_published_model_metadata(self):
        env=dict(TRACEWARD_JUDGE_PROVIDER='openrouter',TRACEWARD_JUDGE_MODEL='vendor/model',OPENROUTER_KEY='router-key')
        answer,_=self.invoke(env,result=response(model='vendor/model-dated'))
        self.assertEqual(answer['status'],'assessed')
        self.assertEqual(answer['requested_model'],'vendor/model')
        self.assertEqual(answer['returned_model'],'vendor/model-dated')
        from traceward.openrouter import canonical_model,model_matches
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return json.dumps({'data':[{'id':'vendor/catalog','canonical_slug':'vendor/catalog-dated'}]}).encode()
        canonical_model.cache_clear()
        with patch('traceward.openrouter.urlopen',return_value=Reply()) as metadata:
            self.assertTrue(model_matches('vendor/catalog','vendor/catalog-dated'))
            self.assertFalse(model_matches('vendor/catalog','other/model'))
            self.assertEqual(metadata.call_count,1)
        canonical_model.cache_clear()
        with patch('traceward.openrouter.urlopen',side_effect=TimeoutError()):
            self.assertFalse(model_matches('vendor/catalog','vendor/catalog-dated'))

    def test_reasoning_details_are_retained_in_the_response_audit(self):
        env=dict(TRACEWARD_JUDGE_PROVIDER='openrouter',TRACEWARD_JUDGE_MODEL='vendor/model',OPENROUTER_KEY='router-key')
        result=response(model='vendor/model')
        details=[{'type':'reasoning.encrypted','data':'synthetic-opaque-data','format':'synthetic-format','index':0}]
        result['choices'][0]['message']['reasoning_details']=details
        answer,_=self.invoke(env,result=result)
        self.assertEqual(answer['status'],'assessed')
        self.assertEqual(answer['response']['choices'][0]['message']['reasoning_details'],details)
