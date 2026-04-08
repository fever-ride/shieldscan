/**
 * Calls the Anthropic API (claude-haiku) to triage a batch of SAST findings.
 * Uses native fetch (Node 18 built-in). No SDK dependency.
 */

const MODEL = 'claude-haiku-4-5-20251001';
const DEFAULT_MAX_FINDINGS = 20; // cost guard — only triage top-N by severity in production

const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

function topFindings(findings, max) {
  return [...findings]
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
    .slice(0, max);
}

function buildPrompt(scanId, findings) {
  const items = findings.map(f => ({
    finding_id: f.finding_id ?? f.id,
    severity:   f.severity,
    rule:       f.rule,
    file:       f.file,
    line:       f.line,
    message:    f.message,
    evidence:   f.evidence ?? '',
    context:    f.context ?? '',   // ±5-line code snippet if available
  }));

  return `You are an application security analyst triaging SAST findings.

Scan ID: ${scanId}
Findings (${items.length}):
${JSON.stringify(items, null, 2)}

For each finding output a JSON object with:
- finding_id  (string, must match input)
- label       ("TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW")
- confidence  (float 0.0–1.0; 1.0 = very confident)
- reasoning   (1–2 sentences explaining why)
- remediation (brief fix suggestion; empty string if FALSE_POSITIVE)

Respond ONLY with valid JSON in this exact shape:
{
  "scan_id": "${scanId}",
  "analyzed_at": "<ISO timestamp>",
  "summary": {
    "total_analyzed": <n>,
    "true_positive": <n>,
    "false_positive": <n>,
    "needs_review": <n>
  },
  "suggestions": [ ... ]
}`;
}

export async function triageFindings(scanId, findings, apiKey, { maxFindings = DEFAULT_MAX_FINDINGS } = {}) {
  if (!findings || findings.length === 0) {
    return {
      scan_id:      scanId,
      analyzed_at:  new Date().toISOString(),
      summary:      { total_analyzed: 0, true_positive: 0, false_positive: 0, needs_review: 0 },
      suggestions:  [],
    };
  }

  const prompt = buildPrompt(scanId, topFindings(findings, maxFindings));

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model:      MODEL,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Anthropic API error ${response.status}: ${body}`);
  }

  const payload = await response.json();
  const text = payload.content?.[0]?.text ?? '';

  // Extract JSON from the response (handle possible markdown fencing)
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('No JSON found in model response');

  return JSON.parse(jsonMatch[0]);
}
