// Pi 0.85.1 observer extension. No tool blocking, rewriting, or verdicts.
import { appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

export default function (pi) {
  let turn = 0;
  let initialInstruction = false;
  const clean = value => String(value ?? '').replace(/\b(?:sk-[A-Za-z0-9_-]{10,}|Bearer\s+\S+)/g, '[REDACTED]')
    .replace(/\b([A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Z_]*\s*[=:]\s*)([^\s,;]+)/gi, '$1[REDACTED]').slice(0, 4096);
  const excerpt = value => clean(value)
    .replace(/SYNTHETIC-ONLY-[a-fA-F0-9]+/g, '[SYNTHETIC_CANARY]')
    .replace(/\b([A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Z_]*\s*[=:]\s*)([^\s,;]+)/gi, '$1[REDACTED]')
    .slice(0, 2048);
  const capture = process.env.TRACEWARD_CONTEXT_MODE === 'redacted';
  const targets = new Map();
  const sensitive = value => /(?:^|[\s/])(?:private|secrets|credentials)(?:[/\s]|$)|(?:\.env|id_rsa|id_ed25519|password|secret|token|credential)/i.test(value);
  const contentText = value => Array.isArray(value) ? value.filter(part => part?.type === 'text').map(part => part.text ?? '').join('\n') : typeof value === 'string' ? value : '';
  const emit = (event, ctx, fields = {}) => {
    try {
      appendFileSync(process.env.TRACEWARD_HOOK_FILE, JSON.stringify({
        source: 'pi_extension', agent: 'pi', event, time: Date.now() / 1000,
        run_id: process.env.TRACEWARD_RUN_ID,
        session_id: ctx.sessionManager.getSessionId(), turn_id: String(turn),
        cwd: ctx.cwd, agent_pid: process.pid, ...fields,
      }) + '\n', { mode: 0o600 });
    } catch { /* Observation must not change the tool outcome. */ }
  };
  pi.on('session_start', (_, ctx) => emit('SessionStart', ctx));
  pi.on('input', (event, ctx) => {
    if (process.env.TRACEWARD_CAPTURE_INITIAL_GOAL !== '1' || initialInstruction ||
        event.source !== 'interactive' || !event.text?.trim()) return;
    initialInstruction = true;
    emit('InitialInstruction', ctx, {input_source: 'interactive', goal_text: clean(event.text)});
  });
  pi.on('turn_start', event => { turn = event.turnIndex; });
  pi.on('tool_call', (event, ctx) => {
    targets.set(event.toolCallId, String(event.input.path ?? event.input.command ?? ''));
    emit('PreToolUse', ctx, {
      tool_use_id: event.toolCallId,
      tool_name: event.toolName === 'bash' ? 'Bash' : event.toolName,
      native_tool_name: event.toolName,
      command: event.toolName === 'bash' ? clean(event.input.command) : '',
      file_targets: event.input.path ? [clean(event.input.path)] : [],
    });
  });
  pi.on('tool_execution_end', (event, ctx) => {
    const result = JSON.stringify(event.result ?? {});
    const text = sensitive(targets.get(event.toolCallId) ?? '') ? '[Sensitive-target content omitted]' :
      contentText(event.result?.content);
    targets.delete(event.toolCallId);
    emit('PostToolUse', ctx, {
      tool_use_id: event.toolCallId, native_tool_name: event.toolName,
      response_sha256: createHash('sha256').update(result).digest('hex'),
      response_bytes: Buffer.byteLength(result),
      result_status: event.isError ? 'error' : 'ok',
      result_exit_code: event.result?.details?.exitCode ?? null,
      ...(capture ? {response_excerpt: excerpt(text)} : {}),
    });
  });
  pi.on('message_end', (event, ctx) => {
    if (!capture || event.message?.role !== 'assistant') return;
    const text = contentText(event.message.content);
    if (text) emit('AgentMessage', ctx, {assistant_excerpt: excerpt(text),
      response_sha256: createHash('sha256').update(text).digest('hex')});
  });
}
