// Pi 0.85.1 observer extension. No tool blocking, rewriting, or verdicts.
import { appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// All events exposed by the pinned Pi 0.85.1 ExtensionAPI. Preserve the
// correlation names for tool_call/tool_execution_end; retain native names too.
export const PI_HOOK_EVENTS = Object.fromEntries([
  'project_trust', 'resources_discover', 'session_start', 'session_info_changed',
  'session_before_switch', 'session_before_fork', 'session_before_compact',
  'session_compact', 'session_compact_failed', 'session_shutdown',
  'session_before_tree', 'session_tree', 'context', 'before_provider_request',
  'before_provider_headers', 'after_provider_response', 'before_agent_start',
  'agent_start', 'agent_end', 'agent_settled', 'ui_prompt_start', 'ui_prompt_end',
  'turn_start', 'turn_end', 'message_start', 'message_update', 'message_end',
  'tool_execution_start', 'tool_execution_update', 'tool_execution_end',
  'model_select', 'thinking_level_select', 'tool_call', 'tool_result', 'user_bash', 'input',
].map(name => [name, name === 'tool_call' ? 'PreToolUse' :
  name === 'tool_execution_end' ? 'PostToolUse' :
  name.replace(/(^|_)([a-z])/g, (_, prefix, letter) => letter.toUpperCase())]));

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
        session_id: ctx.sessionManager?.getSessionId(), turn_id: String(turn),
        cwd: ctx.cwd, agent_pid: process.pid, ...fields,
      }) + '\n', { mode: 0o600 });
    } catch { /* Observation must not change the tool outcome. */ }
  };
  for (const [native, name] of Object.entries(PI_HOOK_EVENTS)) {
    pi.on(native, (event, ctx) => {
      if (native === 'turn_start') turn = event.turnIndex;
      // Never serialize arbitrary event data: provider headers include credentials,
      // and streaming updates include model text, tool output and arguments.
      const metadata = {};
      for (const key of ['reason', 'source', 'position', 'level', 'previousLevel']) {
        if (typeof event[key] === 'string') metadata[key] = clean(event[key]).slice(0, 256);
      }
      for (const key of ['status', 'turnIndex']) {
        if (Number.isFinite(event[key])) metadata[key] = event[key];
      }
      for (const key of ['isError', 'aborted', 'willRetry', 'fromExtension', 'excludeFromContext']) {
        if (typeof event[key] === 'boolean') metadata[key] = event[key];
      }
      if (event.message?.role) metadata.message_role = clean(event.message.role);
      if (event.assistantMessageEvent?.type) metadata.update_type = clean(event.assistantMessageEvent.type);
      if (Array.isArray(event.messages)) metadata.message_count = event.messages.length;
      if (event.model?.id) metadata.model_id = clean(event.model.id);
      if (event.model?.provider) metadata.model_provider = clean(event.model.provider);
      if (native === 'ui_prompt_start' || native === 'ui_prompt_end') metadata.prompt_kind = clean(event.kind);
      const fields = {native_event: native, hook_metadata: metadata};
      if (event.toolCallId) fields.tool_use_id = event.toolCallId;
      if (event.toolName) {
        fields.tool_name = event.toolName === 'bash' ? 'Bash' : event.toolName;
        fields.native_tool_name = event.toolName;
      }
      if (native === 'tool_call') {
        targets.set(event.toolCallId, String(event.input.path ?? event.input.command ?? ''));
        fields.command = event.toolName === 'bash' ? clean(event.input.command) : '';
        fields.file_targets = event.input.path ? [clean(event.input.path)] : [];
      }
      if (native === 'user_bash') fields.command = clean(event.command);
      if (native === 'tool_execution_end') {
        const result = JSON.stringify(event.result ?? {});
        const text = sensitive(targets.get(event.toolCallId) ?? '') ? '[Sensitive-target content omitted]' :
          contentText(event.result?.content);
        targets.delete(event.toolCallId);
        Object.assign(fields, {
          response_sha256: createHash('sha256').update(result).digest('hex'),
          response_bytes: Buffer.byteLength(result),
          result_status: event.isError ? 'error' : 'ok',
          result_exit_code: event.result?.details?.exitCode ?? null,
          ...(capture ? {response_excerpt: excerpt(text)} : {}),
        });
      }
      emit(name, ctx, fields);
      if (native === 'input' && process.env.TRACEWARD_CAPTURE_INITIAL_GOAL === '1' &&
          !initialInstruction && event.source === 'interactive' && event.text?.trim()) {
        initialInstruction = true;
        emit('InitialInstruction', ctx, {input_source: 'interactive', goal_text: clean(event.text)});
      }
      if (native === 'message_end' && capture && event.message?.role === 'assistant') {
        const text = contentText(event.message.content);
        if (text) emit('AgentMessage', ctx, {assistant_excerpt: excerpt(text),
          response_sha256: createHash('sha256').update(text).digest('hex')});
      }
      // Pi requires a result for this control hook. Abstention preserves its
      // normal trust handling; every other handler returns no decision.
      if (native === 'project_trust') return {trusted: 'undecided'};
    });
  }
}
