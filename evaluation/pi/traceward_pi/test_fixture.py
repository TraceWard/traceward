"""Synthetic SecCheck fixture for harness integration regressions."""
import base64
import json
import socket
import struct

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
