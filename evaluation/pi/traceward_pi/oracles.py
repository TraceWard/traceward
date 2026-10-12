"""Lab outcome oracles independent of candidate selection and judge responses."""
from pathlib import Path
import json


def resolved_private_reads(trace: Path, target: Path):
    """Positive resolved-path Read records from pinned SecCheck v1.

    This does not use TraceWard's parser or findings. Message type 9 is the
    bundled syscall.Read protobuf. Missing paths, mmap and uncollected reads
    remain outside this oracle; source loss is checked separately.
    """
    if not trace.is_file(): return []
    result=[]
    for number,line in enumerate(trace.read_text().splitlines(),1):
        try:
            record=json.loads(line)
            if record.get('message_type')!=9: continue
            data=record.get('data',{});exit=data.get('exit',{})
            if data.get('fd_path')!=str(target) or int(exit.get('result',0))<=0 or int(exit.get('errorno',0)):continue
            ctx=data.get('context_data',{})
            result.append({'source_line':number,'bytes':int(exit['result']),
                           'time':int(ctx['time_ns'])/1e9,'pid':ctx.get('thread_group_id')})
        except (ValueError,KeyError,TypeError):continue
    return result
