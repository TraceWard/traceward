"""Structured sensor regressions, including FD semantics and PID reuse."""
import base64
import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from traceward.gvisor import GvisorParser, decode_packet, trace_config
from traceward._gvisor import common_pb2, sentry_pb2, syscall_pb2
from traceward.runner import Receiver


def record(kind, pid=200, time=100.2, start=None, **data):
    return json.dumps({'message_type': kind, 'sandbox_id': 'fixture', 'data': {
        'context_data': {'thread_group_id': pid, 'thread_id': pid,
                         'thread_group_start_time_ns': start or pid * 1000,
                         'time_ns': round(time * 1e9), 'cwd': '/workspace',
                         'parent_thread_group_id': 100}, **data}})


def done(result=0, error=0):
    return {'result': result, 'errorno': error}


def address(port=8800):
    return base64.b64encode(struct.pack('<H', 2) + struct.pack('>H', port)
                            + socket.inet_aton('127.0.0.1') + b'\0' * 8).decode()


def scenario(command='npm test', hidden=True):
    result = [record(2, pid=100, time=100.1, created_thread_group_id=200,
                     created_thread_start_time_ns=200000, flags=0),
              record(3, binary_path='/bin/sh', command_candidates=[command]),
              record(2, time=100.3, created_thread_group_id=201,
                     created_thread_start_time_ns=201000, flags=0),
              record(3, pid=201, time=100.4, binary_path='/usr/bin/node', script_paths=['test.js'])]
    if hidden:
        result += [record(7, pid=201, time=101, pathname='synthetic-credential.txt', fd=-100, exit=done(3)),
                   record(9, pid=201, time=101.1, fd=3, exit=done(16)),
                   record(12, pid=201, time=101.15, exit=done(4)),
                   record(10, pid=201, time=101.2, fd=4, address=address(), exit=done()),
                   record(6, pid=201, time=101.3, arg1=4, sysno=206, exit=done(16))]
    return result


class GvisorTests(unittest.TestCase):
    def setUp(self):
        self.parser = GvisorParser('/workspace')

    def test_open_result_is_descriptor_not_dirfd_and_positive_reads_only(self):
        p = self.parser
        p.parse(record(7, pathname='secret.txt', fd=9, fd_path='/workspace/dir', exit=done(5)))
        self.assertIsNone(p.parse(record(9, fd=5, count=9999, exit=done())))
        e = p.parse(record(9, fd=5, count=9999, exit=done(7)))
        self.assertEqual(e['path'], '/workspace/dir/secret.txt')
        self.assertEqual(e['bytes'], 7)
        self.assertNotIn('count', e)
        failed = p.parse(record(7, pathname='/missing', exit=done(-1, 2)))
        self.assertEqual(failed['operation_status'], 'failed')
        self.assertIsNone(p.parse(record(9, fd=-1, exit=done(-1, 9))))

    def test_dup_fork_shared_socket_description_and_close(self):
        p = self.parser
        p.parse(record(12, exit=done(4)))
        p.parse(record(19, old_fd=4, exit=done(8)))
        p.parse(record(10, fd=4, address=address(), exit=done(-1, 115)))
        send = p.parse(record(34, fd=8, exit=done(33)))
        self.assertEqual(send['endpoint'], '127.0.0.1:8800')
        p.parse(record(2, created_thread_group_id=201, created_thread_start_time_ns=201000, flags=0x400))
        p.parse(record(8, pid=201, fd=8, exit=done()))
        self.assertIsNone(p.parse(record(34, fd=8, exit=done(1))))
        self.assertIsNotNone(p.parse(record(34, fd=4, exit=done(1))))

    def test_pid_reuse_does_not_inherit_descriptors_or_ancestry(self):
        p = self.parser
        p.parse(record(7, pathname='/workspace/credential', exit=done(3)))
        self.assertIsNone(p.parse(record(9, start=999999, fd=3, exit=done(9))))
        self.assertNotEqual(p.parse(record(3, start=999999, binary_path='/bin/sh'))['process_key'], 'fixture:200:200000')

    def test_cloexec_unshares_descriptor_table(self):
        p = self.parser
        p.parse(record(7, pathname='/workspace/a', flags=0x80000, exit=done(3)))
        p.parse(record(2, created_thread_group_id=201, created_thread_start_time_ns=201000, flags=0x400))
        p.parse(record(3, pid=201, binary_path='/bin/sh'))
        self.assertIsNone(p.parse(record(9, pid=201, fd=3, exit=done(2))))
        self.assertIsNotNone(p.parse(record(9, fd=3, exit=done(2))))

    def test_unknown_send_is_a_gap_not_guessed_destination(self):
        self.assertIsNone(self.parser.parse(record(6, arg1=4, arg5=0xdeadbeef, exit=done(9))))
        self.assertTrue(self.parser.gaps)

    def test_sendmmsg_reports_messages_instead_of_bytes(self):
        from traceward.ocsf import project
        for abi,number in [('arm64',269),('amd64',307)]:
            p=GvisorParser('/workspace',abi)
            p.parse(record(12,exit=done(4)))
            p.parse(record(10,fd=4,address=address(),exit=done()))
            effect=p.parse(record(6,arg1=4,sysno=number,exit=done(2)))
            self.assertEqual(effect['message_count'],2)
            self.assertNotIn('bytes',effect)
            exported=project('network_send',effect,'fixture')['unmapped']['traceward']
            self.assertEqual(exported['message_count'],2)
            self.assertNotIn('byte_count',exported)

    def test_wire_header_and_argv_environment_redaction(self):
        c = common_pb2.ContextData(thread_group_id=2, thread_group_start_time_ns=5, time_ns=10)
        msg = sentry_pb2.ExecveInfo(context_data=c, binary_path='/bin/bash',
              argv=['bash', '-lc', 'echo API_KEY=sk-123456789abc'], env=['PASSWORD=DO_NOT_SAVE'])
        item, dropped = decode_packet(struct.pack('<HHI', 8, 3, 7) + msg.SerializeToString(), 's')
        self.assertEqual(dropped, 7)
        self.assertNotIn('DO_NOT_SAVE', json.dumps(item))
        self.assertNotIn('sk-123456789abc', json.dumps(item))
        self.assertNotIn('argv', item['data'])
        for packet in (b'bad', struct.pack('<HHI', 9, 3, 0), struct.pack('<HHI', 8, 999, 0)):
            with self.assertRaises(ValueError):
                decode_packet(packet, 's')

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux SOCK_SEQPACKET receiver")
    def test_receiver_handshake_loss_and_malformed_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receiver = Receiver(root/'s', root/'raw', 'sandbox')
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                peer.connect(str(root/'s'))
                peer.send(common_pb2.Handshake(version=1).SerializeToString())
                self.assertEqual(common_pb2.Handshake.FromString(peer.recv(1024)).version, 1)
                msg = syscall_pb2.Open(context_data=common_pb2.ContextData(thread_group_id=2), pathname='/tmp/a')
                peer.send(struct.pack('<HHI', 8, 7, 3) + msg.SerializeToString())
                peer.send(struct.pack('<HHI', 8, 7, 2) + msg.SerializeToString())
                peer.send(b'bad')
            receiver.close()
            self.assertEqual(receiver.dropped, 3)
            self.assertEqual(receiver.errors, 1)
            self.assertEqual(receiver.messages, 2)
            self.assertEqual((root/'raw').stat().st_mode & 0o777, 0o600)

    def test_abi_required_points_are_explicit(self):
        arm = trace_config('/tmp/a', 'arm64')['trace_session']
        amd = trace_config('/tmp/a', 'amd64')['trace_session']
        self.assertFalse(arm['ignore_missing'])
        self.assertNotIn('syscall/open/exit', {p['name'] for p in arm['points']})
        self.assertIn('syscall/open/exit', {p['name'] for p in amd['points']})
        self.assertTrue(all('env' not in p['optional_fields'] for p in amd['points']))
