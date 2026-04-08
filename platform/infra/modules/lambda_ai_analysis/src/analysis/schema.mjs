/**
 * Manual schema validation for AI triage output.
 * No external dependencies — runs in plain Node 18 Lambda.
 */

const VALID_LABELS = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'NEEDS_REVIEW'];

/**
 * Validates and normalises the raw JSON returned by the model.
 * Returns { ok: true, data } or { ok: false, error }.
 */
export function validateTriageOutput(raw) {
  if (!raw || typeof raw !== 'object') {
    return { ok: false, error: 'response is not an object' };
  }

  const { scan_id, analyzed_at, summary, suggestions } = raw;

  if (typeof scan_id !== 'string') return { ok: false, error: 'missing scan_id' };
  if (!Array.isArray(suggestions)) return { ok: false, error: 'suggestions must be an array' };

  const cleanSuggestions = [];
  for (const s of suggestions) {
    if (typeof s.finding_id !== 'string') continue; // skip malformed entries
    if (!VALID_LABELS.includes(s.label)) {
      s.label = 'NEEDS_REVIEW'; // coerce unexpected values
    }
    if (typeof s.confidence !== 'number' || s.confidence < 0 || s.confidence > 1) {
      s.confidence = 0.5;
    }
    cleanSuggestions.push({
      finding_id:    s.finding_id,
      label:         s.label,
      confidence:    s.confidence,
      reasoning:     typeof s.reasoning === 'string' ? s.reasoning : '',
      remediation:   typeof s.remediation === 'string' ? s.remediation : '',
    });
  }

  return {
    ok: true,
    data: {
      scan_id,
      analyzed_at: typeof analyzed_at === 'string' ? analyzed_at : new Date().toISOString(),
      summary: summary && typeof summary === 'object' ? summary : {},
      suggestions: cleanSuggestions,
    },
  };
}
