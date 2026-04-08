/**
 * ShieldScan — AI Triage Offline Evaluation
 *
 * Runs the SAST scanner on the eval target files, calls the triage pipeline,
 * compares AI labels against the human ground truth, and writes eval/results.json.
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-... node eval/run_eval.mjs
 *
 * Output:
 *   eval/results.json   — full per-finding comparison + summary metrics
 *
 * Precision and recall are defined over the TRUE_POSITIVE class:
 *   precision = TP_correct / (TP_correct + FP_wrong)
 *   recall    = TP_correct / (TP_correct + TP_missed)
 */

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath }               from 'url';
import { dirname, resolve }            from 'path';

// ─── Path resolution ──────────────────────────────────────────────────────────

const __dir     = dirname(fileURLToPath(import.meta.url));
const repoRoot  = resolve(__dir, '..');

// Scanner and triage live inside the Lambda src — import directly for offline use
const scannerPath = resolve(repoRoot, 'platform/infra/modules/lambda_sast/src/scanner/scanner.mjs');
const triagePath  = resolve(repoRoot, 'platform/infra/modules/lambda_ai_analysis/src/analysis/triage.mjs');

const { scanCode }        = await import(scannerPath);
const { triageFindings }  = await import(triagePath);

// ─── Config ───────────────────────────────────────────────────────────────────

const API_KEY = process.env.ANTHROPIC_API_KEY;
if (!API_KEY) {
  console.error('Error: ANTHROPIC_API_KEY environment variable not set.');
  process.exit(1);
}

const TARGET_FILES = [
  resolve(repoRoot, 'eval/target/vulnerable.js'),
  resolve(repoRoot, 'eval/target/false_positives.js'),
];

const GROUND_TRUTH_PATH = resolve(__dir, 'ground_truth.json');
const RESULTS_PATH      = resolve(__dir, 'results.json');

// ─── Step 1: Run SAST scanner ─────────────────────────────────────────────────

// Mirror what index.mjs does: extract ±5-line code context per finding so
// the triage prompt receives the same `context` field as in production.
function extractContext(code, lineNumber, windowSize = 5) {
  if (!code || !lineNumber) return '';
  const lines = code.split('\n');
  const start = Math.max(0, lineNumber - 1 - windowSize);
  const end   = Math.min(lines.length, lineNumber - 1 + windowSize + 1);
  return lines.slice(start, end).join('\n');
}

console.log('\n[1/4] Running SAST scanner...');

const allFindings = [];
for (const absPath of TARGET_FILES) {
  const relPath = absPath.replace(repoRoot + '/', '');
  const code    = readFileSync(absPath, 'utf-8');
  const findings = scanCode(code, relPath);
  // Attach code context — keeps eval input identical to the production path
  for (const f of findings) {
    f.context = extractContext(code, f.line);
  }
  allFindings.push(...findings);
  console.log(`  ${relPath}: ${findings.length} finding(s)`);
}

console.log(`  Total: ${allFindings.length} finding(s)`);

// ─── Step 2: Load ground truth ────────────────────────────────────────────────

console.log('\n[2/4] Loading ground truth...');

const { findings: gtList } = JSON.parse(readFileSync(GROUND_TRUTH_PATH, 'utf-8'));
const groundTruth = Object.fromEntries(gtList.map(g => [g.finding_id, g]));

// Warn about any scanner findings not in ground truth (need manual labelling)
let unlabelled = 0;
for (const f of allFindings) {
  if (!groundTruth[f.finding_id]) {
    console.warn(`  WARNING: no ground truth for ${f.finding_id}`);
    unlabelled++;
  }
}
if (unlabelled === 0) console.log(`  All ${allFindings.length} findings have ground truth labels.`);

// ─── Step 3: AI triage ───────────────────────────────────────────────────────

console.log('\n[3/4] Calling AI triage (claude-haiku)...');
const scanId = `eval-${new Date().toISOString().slice(0, 10)}`;

let triageResult;
try {
  // Override the production cost guard so all eval findings are triaged
  triageResult = await triageFindings(scanId, allFindings, API_KEY, { maxFindings: allFindings.length });
  console.log(`  AI analyzed ${triageResult.summary?.total_analyzed} finding(s)`);
  console.log(`  AI summary: TP=${triageResult.summary?.true_positive} FP=${triageResult.summary?.false_positive} NR=${triageResult.summary?.needs_review}`);
} catch (err) {
  console.error('  Triage API call failed:', err.message);
  process.exit(1);
}

// Index AI suggestions by finding_id
const aiByFindingId = Object.fromEntries(
  (triageResult.suggestions ?? []).map(s => [s.finding_id, s])
);

// ─── Step 4: Compare and compute metrics ─────────────────────────────────────

console.log('\n[4/4] Computing metrics...');

/**
 * Maps AI labels to binary TP/FP for comparison with ground truth.
 *
 * Ground truth has two classes: TRUE_POSITIVE and FALSE_POSITIVE.
 * AI has three: TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_REVIEW.
 *
 * For precision/recall we treat NEEDS_REVIEW as a predicted positive
 * (conservative: if AI isn't sure, it shouldn't dismiss it).
 */
const aiPredictedPositive = (label) =>
  label === 'TRUE_POSITIVE' || label === 'NEEDS_REVIEW';

const comparison = allFindings.map(f => {
  const gt  = groundTruth[f.finding_id];
  const ai  = aiByFindingId[f.finding_id];

  const gtLabel  = gt?.ground_truth   ?? 'UNKNOWN';
  const aiLabel  = ai?.label          ?? 'NOT_TRIAGED';
  const aiConf   = ai?.confidence     ?? null;
  const aiReason = ai?.reasoning      ?? '';

  // Outcome classification (relative to TRUE_POSITIVE as the positive class)
  let outcome;
  const gtIsPos = gtLabel === 'TRUE_POSITIVE';
  const aiIsPos = aiPredictedPositive(aiLabel);

  if      ( gtIsPos &&  aiIsPos) outcome = 'TP';  // correctly identified as positive
  else if ( gtIsPos && !aiIsPos) outcome = 'FN';  // missed — false negative
  else if (!gtIsPos &&  aiIsPos) outcome = 'FP';  // over-flagged — false positive
  else                           outcome = 'TN';  // correctly identified as negative

  return {
    finding_id:    f.finding_id,
    rule:          f.id,
    severity:      f.severity,
    file:          f.file,
    line:          f.line,
    gt_label:      gtLabel,
    gt_notes:      gt?.notes ?? '',
    ai_label:      aiLabel,
    ai_confidence: aiConf,
    ai_reasoning:  aiReason,
    outcome,
  };
});

// Aggregate counts
const counts = comparison.reduce(
  (acc, r) => { acc[r.outcome] = (acc[r.outcome] ?? 0) + 1; return acc; },
  { TP: 0, FN: 0, FP: 0, TN: 0 }
);

const precision = counts.TP / (counts.TP + counts.FP) || 0;
const recall    = counts.TP / (counts.TP + counts.FN) || 0;
const f1        = precision + recall > 0
  ? (2 * precision * recall) / (precision + recall)
  : 0;
const accuracy  = (counts.TP + counts.TN) / comparison.length || 0;

// Label distribution for AI output
const aiDist = (triageResult.suggestions ?? []).reduce((acc, s) => {
  acc[s.label] = (acc[s.label] ?? 0) + 1;
  return acc;
}, {});

const metrics = {
  total_findings:   comparison.length,
  ground_truth_distribution: {
    true_positive:  comparison.filter(r => r.gt_label === 'TRUE_POSITIVE').length,
    false_positive: comparison.filter(r => r.gt_label === 'FALSE_POSITIVE').length,
  },
  ai_label_distribution: aiDist,
  confusion_matrix: counts,
  precision:  parseFloat(precision.toFixed(4)),
  recall:     parseFloat(recall.toFixed(4)),
  f1_score:   parseFloat(f1.toFixed(4)),
  accuracy:   parseFloat(accuracy.toFixed(4)),
  note: "NEEDS_REVIEW treated as predicted positive (conservative) for precision/recall calculation",
};

console.log(`\n  Confusion matrix: TP=${counts.TP}  FN=${counts.FN}  FP=${counts.FP}  TN=${counts.TN}`);
console.log(`  Precision: ${(precision * 100).toFixed(1)}%`);
console.log(`  Recall:    ${(recall * 100).toFixed(1)}%`);
console.log(`  F1:        ${(f1 * 100).toFixed(1)}%`);
console.log(`  Accuracy:  ${(accuracy * 100).toFixed(1)}%`);

// ─── Write results ────────────────────────────────────────────────────────────

const output = {
  scan_id:    scanId,
  ran_at:     new Date().toISOString(),
  model:      'claude-haiku-4-5-20251001',
  metrics,
  per_finding: comparison,
};

writeFileSync(RESULTS_PATH, JSON.stringify(output, null, 2));
console.log(`\nResults written to eval/results.json`);

// ─── Print mismatches for quick review ───────────────────────────────────────

const mismatches = comparison.filter(r => r.outcome === 'FN' || r.outcome === 'FP');
if (mismatches.length > 0) {
  console.log(`\nMismatches (${mismatches.length}):`);
  for (const r of mismatches) {
    const symbol = r.outcome === 'FN' ? '✗ FN (missed real vuln)' : '~ FP (over-flagged)';
    console.log(`  ${symbol}: ${r.finding_id}`);
    console.log(`    GT: ${r.gt_label} | AI: ${r.ai_label} (conf=${r.ai_confidence?.toFixed(2)})`);
    console.log(`    AI reasoning: ${r.ai_reasoning.slice(0, 100)}...`);
  }
}
