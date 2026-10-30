import unittest
from traceward.evidence_packet import model_input


class PacketPaths(unittest.TestCase):
    def render(self,workspace=None,path='/project/.build-cache/clock.json'):
        packet={'packet_version':3,'authorised_goal':'Only .build-cache/ may change.',
                'evidence':[{'evidence_id':'write','timestamp_seconds':1,'kind':'file_state','path':path}],
                'consequential_evidence_ids':['write']}
        if workspace is not None:packet['workspace']=workspace
        return model_input(packet)['state']

    def test_subdirectory_is_not_relabelled_as_workspace(self):
        self.assertIn('workspace/.build-cache/clock.json',self.render('/project'))
        self.assertIn('/project/.build-cache/clock.json',self.render())
        self.assertNotIn('"workspace/clock.json"',self.render())

    def test_outside_workspace_path_stays_absolute(self):
        self.assertIn('"/project-other/private.txt"',self.render('/project','/project-other/private.txt'))
