/**
 * ReAct Agent — deep investigation of a single SAST finding.
 * Uses Anthropic tool use (native fetch, no SDK).
 *
 * Guardrails:
 *   - max MAX_TOOL_CALLS tool calls per run
 *   - TIMEOUT_MS overall wall-clock timeout
 *   - validateAgentOutput() normalises the final verdict
 *   - one schema-retry if verdict not parseable on first end_turn
 */
import { TOOL_DEFINITIONS, callTool } from './tools.mjs';

const MODEL          = 'claude-sonnet-4-6';
const MAX_TOOL_CALLS = 10;
const TIMEOUT_MS     = 3 * 60 * 1000; // 3 minutes

const VALID_VERDICTS = ['CONFIRMED', 'LIKELY_FALSE_POSITIVE', 'INCONCLUSIVE'];

// ─── Output validation ────────────────────────────────────────────────────────

/**
 * Validates and normalises a raw agent verdict object.
 * Returns { ok: true, data } or { ok: false, error }.
 */
function validateAgentOutput(raw) {
  if (!raw || typeof raw !== 'object') return { ok: false, error: 'not an object' };

  const verdict = VALID_VERDICTS.includes(raw.verdict) ? raw.verdict : null;
  if (!verdict) return { ok: false, error: `invalid verdict: ${raw.verdict}` };

  let confidence = typeof raw.confidence === 'number' ? raw.confidence : parseFloat(raw.confidence);
  if (isNaN(confidence) || confidence < 0 || confidence > 1) confidence = 0.5;

  return {
    ok: true,
    data: {
      finding_id:  typeof raw.finding_id === 'string' ? raw.finding_id : '',
      verdict,
      confidence,
      attack_path: typeof raw.attack_path === 'string'  ? raw.attack_path  : '',
      remediation: typeof raw.remediation === 'string'  ? raw.remediation  : '',
    },
  };
}

// ─── Anthropic API ────────────────────────────────────────────────────────────

async function anthropicCall(apiKey, messages, maxTokens = 4096) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model:      MODEL,
      max_tokens: maxTokens,
      tools:      TOOL_DEFINITIONS,
      messages,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Anthropic API ${res.status}: ${body}`);
  }
  return res.json();
}

// ─── Prompt ───────────────────────────────────────────────────────────────────

function buildUserPrompt(finding, dastContext) {
  const repo   = finding.repo_name ?? 'unknown';
  const branch = finding.branch    ?? 'main';

  const dastSection = dastContext
    ? `\n\n## DAST Results (same app, recent pentest)\n${JSON.stringify(dastContext, null, 2)}`
    : '';

  return `You are a security researcher investigating a SAST finding.

## Repository
repo:   ${repo}
branch: ${branch}

Use **ref="${branch}"** when calling get_file_context and get_directory_tree so you query
the exact version that was scanned, not a later commit.
Note: search_code searches the default branch only — use it for symbol discovery, not
as the sole source of truth for whether a vulnerability exists.

## Finding
${JSON.stringify(finding, null, 2)}
${dastSection}

Investigate whether this finding is exploitable. Check how the flagged code is called,
whether user-controlled input reaches it unsanitised, and whether defences exist.

When done, output a verdict JSON — **no other text after it**:
{
  "finding_id": "${finding.finding_id}",
  "verdict": "CONFIRMED" | "LIKELY_FALSE_POSITIVE" | "INCONCLUSIVE",
  "confidence": <float 0.0-1.0>,
  "attack_path": "<exploitation path or reason it is not exploitable>",
  "remediation": "<specific fix>"
}

Budget: at most ${MAX_TOOL_CALLS} tool calls.`;
}

// ─── JSON extraction ──────────────────────────────────────────────────────────

function extractRawVerdict(text) {
  const match = text.match(/\{[\s\S]*?"verdict"[\s\S]*?\}/);
  if (!match) return null;
  try { return JSON.parse(match[0]); } catch { return null; }
}

// ─── ReAct loop ───────────────────────────────────────────────────────────────

async function runLoop(finding, apiKey, dastContext) {
  const messages = [{ role: 'user', content: buildUserPrompt(finding, dastContext) }];

  // investigation trace — tool calls + results
  const trace      = [];
  let toolCallCount = 0;
  let rawVerdict    = null;

  while (toolCallCount < MAX_TOOL_CALLS) {
    const response = await anthropicCall(apiKey, messages);
    messages.push({ role: 'assistant', content: response.content });

    const textBlock = response.content.find(b => b.type === 'text');
    if (textBlock) {
      const candidate = extractRawVerdict(textBlock.text);
      if (candidate) rawVerdict = candidate;
    }

    if (response.stop_reason === 'end_turn') break;
    if (response.stop_reason !== 'tool_use') break;

    const toolUseBlocks = response.content.filter(b => b.type === 'tool_use');
    const toolResults   = [];

    for (const block of toolUseBlocks) {
      if (toolCallCount >= MAX_TOOL_CALLS) break;
      const output = await callTool(block.name, block.input);
      toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: output });
      trace.push({
        step:   trace.length + 1,
        tool:   block.name,
        input:  block.input,
        output: output.length > 600 ? output.slice(0, 600) + '\n...[truncated]' : output,
      });
      toolCallCount++;
    }

    messages.push({ role: 'user', content: toolResults });
  }

  // Schema retry — one extra turn to force structured output
  if (!rawVerdict) {
    console.warn(`Agent: no verdict after loop for ${finding.finding_id}, forcing retry`);
    const retryResponse = await anthropicCall(apiKey, [
      ...messages,
      { role: 'user', content: 'Output your final verdict JSON now. No tool calls. Follow the exact schema.' },
    ], 512);
    const retryText = retryResponse.content.find(b => b.type === 'text');
    if (retryText) rawVerdict = extractRawVerdict(retryText.text);
  }

  // Validate and normalise verdict
  const validation = validateAgentOutput(rawVerdict ?? {});
  if (!validation.ok) {
    console.warn(`Agent output validation failed for ${finding.finding_id}: ${validation.error}`);
  }
  const verdict = validation.ok ? validation.data : null;

  return {
    finding_id:      finding.finding_id,
    verdict:         verdict?.verdict     ?? 'INCONCLUSIVE',
    confidence:      verdict?.confidence  ?? 0.5,
    attack_path:     verdict?.attack_path ?? '',
    remediation:     verdict?.remediation ?? '',
    // "investigation trace" — tool call sequence used by the agent
    investigation_trace: trace,
    tool_calls_used: toolCallCount,
    ...(validation.ok ? {} : { validation_error: validation.error }),
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function investigateFinding(finding, apiKey, dastContext = null) {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Agent timeout (3 min)')), TIMEOUT_MS)
  );
  return Promise.race([runLoop(finding, apiKey, dastContext), timeout]);
}
