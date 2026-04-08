/**
 * AI Analysis Lambda
 * Triggered by SNS sast_complete topic.
 * Reads S3 SAST report → calls Claude → writes ai/{scan_id}.json + updates DynamoDB.
 */
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { triageFindings } from './triage.mjs';
import { validateTriageOutput } from './schema.mjs';
import { investigateFinding } from './agent.mjs';
import { getDastContext } from './correlate.mjs';
import { emitMetric } from './emf.mjs';

const s3     = new S3Client({});
const dynamo = new DynamoDBClient({});

const BUCKET         = process.env.REPORTS_BUCKET_NAME;
const SCANS_TABLE    = process.env.SCANS_TABLE_NAME;
const ANTHROPIC_KEY  = process.env.ANTHROPIC_API_KEY;
const AI_ENABLED     = process.env.AI_ANALYSIS_ENABLED === 'true';

const AGENT_TOP_N = 3; // investigate only top N HIGH findings

async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf-8');
}

async function getReport(reportKey) {
  const obj = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: reportKey }));
  const text = await streamToString(obj.Body);
  return JSON.parse(text);
}

async function putAiReport(scanId, data) {
  await s3.send(new PutObjectCommand({
    Bucket:      BUCKET,
    Key:         `ai/${scanId}.json`,
    Body:        JSON.stringify(data, null, 2),
    ContentType: 'application/json',
  }));
}

async function putAgentReport(scanId, results) {
  await s3.send(new PutObjectCommand({
    Bucket:      BUCKET,
    Key:         `ai/agent/${scanId}.json`,
    Body:        JSON.stringify({ scan_id: scanId, investigated_at: new Date().toISOString(), results }, null, 2),
    ContentType: 'application/json',
  }));
}

async function updateScanRecord(scanId, summary) {
  await dynamo.send(new UpdateItemCommand({
    TableName: SCANS_TABLE,
    Key:       { scan_id: { S: scanId } },
    UpdateExpression: 'SET ai_analyzed = :t, ai_status = :s, ai_true_positive = :tp, ai_false_positive = :fp, ai_needs_review = :nr, ai_analyzed_at = :at',
    ExpressionAttributeValues: {
      ':t':  { BOOL: true },
      ':s':  { S: 'success' },
      ':tp': { N: String(summary.true_positive  ?? 0) },
      ':fp': { N: String(summary.false_positive ?? 0) },
      ':nr': { N: String(summary.needs_review   ?? 0) },
      ':at': { S: new Date().toISOString() },
    },
  }));
}

async function writeScanError(scanId, message) {
  try {
    await dynamo.send(new UpdateItemCommand({
      TableName: SCANS_TABLE,
      Key:       { scan_id: { S: scanId } },
      UpdateExpression: 'SET ai_analyzed = :f, ai_status = :s, ai_error_message = :e, ai_analyzed_at = :at',
      ExpressionAttributeValues: {
        ':f':  { BOOL: false },
        ':s':  { S: 'error' },
        ':e':  { S: message },
        ':at': { S: new Date().toISOString() },
      },
    }));
  } catch (writeErr) {
    console.error('Failed to write error status to DynamoDB:', writeErr);
  }
}

async function processRecord(record) {
  // SNS message body
  const snsMsg  = JSON.parse(record.Sns.Message);
  const scanId  = snsMsg.scan_id;
  const s3Key   = snsMsg.report_s3_key ?? `sast/${scanId}.json`;

  console.log(`AI analysis: ${scanId} (report: ${s3Key})`);

  const report   = await getReport(s3Key);
  // SAST reports use 'vulnerabilities'; support both field names
  const findings = report.vulnerabilities ?? report.findings ?? [];

  // Only triage HIGH + MEDIUM to control cost
  const relevant = findings.filter(f => ['HIGH', 'MEDIUM'].includes(f.severity));
  if (relevant.length === 0) {
    console.log(`${scanId}: no HIGH/MEDIUM findings — skipping AI call`);
    emitMetric('ai_triage_total', 1, { status: 'skipped' });
    return;
  }

  const rawOutput  = await triageFindings(scanId, relevant, ANTHROPIC_KEY);
  const validation = validateTriageOutput(rawOutput);

  if (!validation.ok) {
    console.error(`Schema validation failed for ${scanId}: ${validation.error}`);
    await writeScanError(scanId, `Schema validation failed: ${validation.error}`);
    emitMetric('ai_triage_total', 1, { status: 'error' });
    return;
  }

  const triageData = validation.data;

  await Promise.all([
    putAiReport(scanId, triageData),
    updateScanRecord(scanId, triageData.summary),
  ]);

  emitMetric('ai_triage_total', 1, { status: 'success' });
  console.log(`${scanId}: AI triage written — ${JSON.stringify(triageData.summary)}`);

  // ── Deep investigation: top AGENT_TOP_N HIGH findings ──────────────────────
  const repoName = report.repo_name;
  const branch   = report.branch ?? 'main';

  const topHigh = findings
    .filter(f => f.severity === 'HIGH' && f.finding_id)
    .slice(0, AGENT_TOP_N)
    // Stamp each finding with repo/branch so tools can pin to the right version
    .map(f => ({ ...f, repo_name: repoName, branch }));

  if (topHigh.length > 0) {
    const appId      = snsMsg.app_id ?? null;
    const dastCtx    = await getDastContext(appId);
    if (dastCtx) console.log(`${scanId}: DAST context found (${dastCtx.failures.length} failures)`);

    // Run investigations in parallel — each has its own 3-min timeout
    const agentStart   = Date.now();
    const agentResults = await Promise.allSettled(
      topHigh.map(f => investigateFinding(f, ANTHROPIC_KEY, dastCtx))
    );
    const agentDuration = Date.now() - agentStart;

    const results = agentResults.map((r, i) =>
      r.status === 'fulfilled'
        ? r.value
        : { finding_id: topHigh[i].finding_id, verdict: 'INCONCLUSIVE', confidence: 0, error: r.reason?.message }
    );

    // Emit per-verdict counts + overall duration
    for (const r of results) {
      emitMetric('agent_investigations_total', 1, { verdict: r.verdict });
    }
    emitMetric('agent_duration_ms', agentDuration, {}, 'Milliseconds');

    await putAgentReport(scanId, results);

    // Update DynamoDB: mark agent analysis done
    await dynamo.send(new UpdateItemCommand({
      TableName: SCANS_TABLE,
      Key:       { scan_id: { S: scanId } },
      UpdateExpression: 'SET ai_agent_analyzed = :t, ai_agent_count = :n',
      ExpressionAttributeValues: {
        ':t': { BOOL: true },
        ':n': { N: String(results.length) },
      },
    }));

    const confirmed = results.filter(r => r.verdict === 'CONFIRMED').length;
    console.log(`${scanId}: Agent done — ${results.length} investigated, ${confirmed} CONFIRMED`);
  }
}

export async function handler(event) {
  if (!AI_ENABLED) {
    console.log('AI_ANALYSIS_ENABLED=false — skipping');
    return;
  }
  if (!ANTHROPIC_KEY) {
    console.error('ANTHROPIC_API_KEY not set');
    return;
  }

  const records = event.Records ?? [];
  for (const record of records) {
    try {
      await processRecord(record);
    } catch (err) {
      console.error('Error processing record:', err);
      // Best-effort: write error status; don't rethrow to avoid SNS retry loop
      const scanId = (() => { try { return JSON.parse(record.Sns?.Message)?.scan_id; } catch { return null; } })();
      if (scanId) await writeScanError(scanId, err.message);
    }
  }
}
