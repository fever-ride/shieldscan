/**
 * SAST Scanner Lambda
 * Triggered by SQS → fetches code from GitHub → runs scanCode() → writes DynamoDB + S3
 */
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { scanCode } from './scanner.mjs';
import { emitMetric } from './emf.mjs';
import { toSarif } from './sarif.mjs';

const dynamo = new DynamoDBClient({});
const s3 = new S3Client({});
const sns = new SNSClient({});

const TABLE_NAME             = process.env.SCANS_TABLE_NAME;
const APPS_TABLE             = process.env.APPS_TABLE_NAME;
const BUCKET_NAME            = process.env.REPORTS_BUCKET_NAME;
const SNS_TOPIC_ARN          = process.env.SNS_TOPIC_ARN;
const SAST_COMPLETE_TOPIC_ARN = process.env.SAST_COMPLETE_TOPIC_ARN;
const GITHUB_TOKEN           = process.env.GITHUB_TOKEN;

// ─── Code context extraction ─────────────────────────────────────────────────

/** Returns up to `windowSize` lines before and after `lineNumber` (1-based). */
function extractContext(code, lineNumber, windowSize = 5) {
  if (!code || !lineNumber) return '';
  const lines  = code.split('\n');
  const start  = Math.max(0, lineNumber - 1 - windowSize);
  const end    = Math.min(lines.length, lineNumber - 1 + windowSize + 1);
  return lines.slice(start, end).join('\n');
}

// ─── GitHub helpers ───────────────────────────────────────────────────────────

function githubHeaders() {
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'shieldscan-sast',
    ...(GITHUB_TOKEN && { Authorization: `Bearer ${GITHUB_TOKEN}` }),
  };
}

/** Returns the app_id for a repo, or null if no app is registered for it. */
async function lookupAppId(repoName) {
  if (!APPS_TABLE || !repoName) return null;
  try {
    const result = await dynamo.send(new QueryCommand({
      TableName: APPS_TABLE,
      IndexName: 'repo-index',
      KeyConditionExpression: 'repo_name = :repo',
      ExpressionAttributeValues: { ':repo': { S: repoName } },
      Limit: 1,
    }));
    return result.Items?.[0]?.app_id?.S ?? null;
  } catch (err) {
    console.warn('lookupAppId failed:', err.message);
    return null;
  }
}

/** Returns true if this repo has at least one prior completed scan. */
async function hasPriorScan(repoName) {
  const result = await dynamo.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'repo-time-index',
    KeyConditionExpression: 'repo_name = :repo',
    FilterExpression: '#s = :completed',
    ExpressionAttributeNames: { '#s': 'status' },
    ExpressionAttributeValues: {
      ':repo': { S: repoName },
      ':completed': { S: 'completed' },
    },
    Limit: 1,
    ScanIndexForward: false,
  }));
  return (result.Items?.length ?? 0) > 0;
}

/** Returns the set of filenames changed in a PR (file-level granularity). */
async function getPrDiffFiles(repoName, prNumber) {
  const res = await fetch(
    `https://api.github.com/repos/${repoName}/pulls/${prNumber}/files?per_page=100`,
    { headers: githubHeaders() }
  );
  if (!res.ok) throw new Error(`GitHub PR files API: ${res.status}`);
  const files = await res.json();
  return new Set(files.map(f => f.filename));
}

// ─── PR comment ───────────────────────────────────────────────────────────────

const COMMENT_MAX_CHARS = 62000;
const SEV_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2 };

function sortFindings(vulns) {
  return [...vulns].sort((a, b) => {
    const sd = (SEV_ORDER[a.severity] ?? 3) - (SEV_ORDER[b.severity] ?? 3);
    if (sd !== 0) return sd;
    if (a.file !== b.file) return (a.file || '').localeCompare(b.file || '');
    return (a.line || 0) - (b.line || 0);
  });
}

function formatFinding(v, i) {
  const detail = v.description ? `\n  - detail: ${v.description}` : '';
  const evidence = v.evidence
    ? `\n  - evidence: \`${String(v.evidence).replace(/`/g, "'")}\``
    : '';
  return [
    `#### ${i + 1}. \`${v.id}\` (${v.severity}) — ${v.name}`,
    `- **File:** \`${v.file}:${v.line}\``,
    `- **Message:** ${v.message}${detail}${evidence}`,
  ].join('\n');
}

async function postPrComment({ repoName, prNumber, summary, vulnerabilities, scanId, isFirstScan }) {
  if (!GITHUB_TOKEN || !repoName || !prNumber) return;
  if (!repoName.includes('/')) return;

  const [owner, repo] = repoName.split('/');
  const sorted = sortFindings(vulnerabilities);
  const scanScope = isFirstScan ? 'Full repository scan' : 'Changed files only';

  const header = [
    `## ShieldScan SAST Results`,
    ``,
    `**Scan ID:** \`${scanId}\` · **Scope:** ${scanScope}`,
    `**Severity:** HIGH=${summary.high} MEDIUM=${summary.medium} LOW=${summary.low} (total=${summary.totalVulnerabilities})`,
    `**Files scanned:** ${summary.totalFiles}`,
    ``,
    `### Findings (${sorted.length})`,
    ``,
  ].join('\n');

  let body = header;
  let included = 0;
  for (let i = 0; i < sorted.length; i++) {
    const block = formatFinding(sorted[i], i) + '\n\n';
    if (body.length + block.length > COMMENT_MAX_CHARS) {
      body += `\n---\n*${sorted.length - included} more finding(s) omitted — GitHub comment limit reached. Full report in S3: \`${scanId}.json\`*\n`;
      break;
    }
    body += block;
    included++;
  }

  if (sorted.length === 0) {
    body += '_No vulnerabilities detected._\n';
  }

  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments`,
    {
      method: 'POST',
      headers: { ...githubHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ body }),
    }
  );

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`PR comment failed (${res.status}): ${text}`);
  }
}

async function fetchCodeFromGithub(cloneUrl, branch, repo, allowedPaths = null) {
  const apiBase = `https://api.github.com/repos/${repo}`;
  const headers = githubHeaders();

  const treeRes = await fetch(`${apiBase}/git/trees/${branch}?recursive=1`, { headers });
  if (!treeRes.ok) throw new Error(`GitHub API error: ${treeRes.status}`);
  const tree = await treeRes.json();

  // Directories that are high-risk and should be scanned first
  const HIGH_PRIORITY_DIRS = ['routes', 'controllers', 'auth', 'middleware', 'api', 'security', 'handlers'];

  const isTestFile = (path) =>
    /\.(test|spec)\.[jt]sx?$/.test(path) ||
    path.includes('/__tests__/') ||
    path.includes('/test/') ||
    path.includes('/tests/') ||
    path.includes('/fixtures/') ||
    path.includes('/mocks/');

  const filePriority = (path) => {
    const idx = HIGH_PRIORITY_DIRS.findIndex(dir =>
      path.includes(`/${dir}/`) || path.startsWith(`${dir}/`)
    );
    return idx === -1 ? HIGH_PRIORITY_DIRS.length : idx;
  };

  const supportedFiles = tree.tree
    .filter(f =>
      f.type === 'blob' &&
      /\.(js|mjs|cjs|jsx|ts|tsx|py|java|go)$/.test(f.path) &&
      !f.path.includes('node_modules') &&
      !f.path.includes('dist/') &&
      !f.path.includes('vendor/') &&
      !f.path.includes('.min.') &&
      !isTestFile(f.path) &&
      (allowedPaths === null || allowedPaths.has(f.path))
    )
    .sort((a, b) => filePriority(a.path) - filePriority(b.path));

  const filesToFetch = supportedFiles.slice(0, 100);
  const CONCURRENCY = 10;
  const files = [];

  for (let i = 0; i < filesToFetch.length; i += CONCURRENCY) {
    const batch = filesToFetch.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async (file) => {
        const contentRes = await fetch(`${apiBase}/contents/${file.path}?ref=${branch}`, { headers });
        if (!contentRes.ok) return null;
        const contentData = await contentRes.json();
        const code = Buffer.from(contentData.content, 'base64').toString('utf-8');
        return { path: file.path, code };
      })
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        files.push(result.value);
      } else if (result.status === 'rejected') {
        console.warn('Failed to fetch file:', result.reason?.message);
      }
    }
  }

  return files;
}

// ─── GitHub Code Scanning SARIF upload ───────────────────────────────────────

/**
 * Uploads a SARIF document to GitHub Code Scanning via the REST API.
 * Requires the GitHub token to have the `security_events` write scope.
 *
 * @param {object} opts
 * @param {string} opts.repoName  - "owner/repo"
 * @param {string} opts.branch    - branch name (for ref resolution)
 * @param {object} opts.sarifDoc  - SARIF 2.1.0 document object
 * @param {string} opts.scanId    - scan_id for logging
 */
async function uploadSarifToGithub({ repoName, branch, sarifDoc, scanId }) {
  const [owner, repo] = repoName.split('/');

  // Resolve the HEAD commit SHA for the branch
  const refRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${branch}`,
    { headers: githubHeaders() }
  );
  if (!refRes.ok) {
    throw new Error(`Could not resolve branch ref: ${refRes.status}`);
  }
  const refData = await refRes.json();
  const commitSha = refData.object?.sha;
  if (!commitSha) throw new Error('commit SHA not found in ref response');

  // GitHub requires SARIF content gzip-compressed and base64-encoded
  const sarifJson = JSON.stringify(sarifDoc);
  // Node 18 has no built-in zlib in ESM without dynamic import; send uncompressed
  // (GitHub accepts uncompressed SARIF too — gzip is optional for performance)
  const sarifBase64 = Buffer.from(sarifJson).toString('base64');

  const uploadRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/code-scanning/sarifs`,
    {
      method: 'POST',
      headers: { ...githubHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        commit_sha: commitSha,
        ref: `refs/heads/${branch}`,
        sarif: sarifBase64,
        tool_name: 'ShieldScan',
      }),
    }
  );

  if (!uploadRes.ok) {
    const text = await uploadRes.text().catch(() => '');
    throw new Error(`GitHub SARIF upload ${uploadRes.status}: ${text}`);
  }

  const uploadData = await uploadRes.json();
  console.log(`GitHub SARIF upload queued: ${uploadData.url} (scan_id=${scanId})`);
}

export const handler = async (event) => {
  for (const record of event.Records) {
    const job = JSON.parse(record.body);
    const { scan_id, repo_name, pr_number, branch, clone_url } = job;

    console.log(`Processing SAST scan: ${scan_id} for ${repo_name}`);
    const scanStart = Date.now();

    try {
      // Resolve app_id and scan scope in parallel
      const [appId, priorScanExists] = await Promise.all([
        lookupAppId(repo_name),
        hasPriorScan(repo_name),
      ]);
      const isFirstScan = !priorScanExists;
      let allowedPaths = null; // null = full scan

      if (!isFirstScan && pr_number) {
        try {
          allowedPaths = await getPrDiffFiles(repo_name, pr_number);
          console.log(`Diff-scoped scan: ${allowedPaths.size} changed files`);
        } catch (diffErr) {
          // Fall back to full scan if diff fetch fails
          console.warn('Failed to get PR diff, falling back to full scan:', diffErr.message);
        }
      }

      console.log(`Scan scope: ${isFirstScan ? 'full repo (first scan)' : allowedPaths ? `diff (${allowedPaths.size} files)` : 'full repo (fallback)'}`);

      const files = await fetchCodeFromGithub(clone_url, branch, repo_name, allowedPaths);

      const allVulnerabilities = [];
      for (const file of files) {
        const vulns = scanCode(file.code, file.path);
        // Attach ±5-line code context to each finding for AI triage
        for (const v of vulns) {
          v.context = extractContext(file.code, v.line);
        }
        allVulnerabilities.push(...vulns);
      }

      const summary = {
        totalFiles: files.length,
        totalVulnerabilities: allVulnerabilities.length,
        high: allVulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: allVulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: allVulnerabilities.filter(v => v.severity === 'LOW').length
      };

      const maxSeverity = summary.high > 0 ? 'HIGH' : summary.medium > 0 ? 'MEDIUM' : summary.low > 0 ? 'LOW' : 'NONE';

      const reportKey = `sast/${scan_id}.json`;
      const fullReport = {
        scan_id, scan_type: 'sast', repo_name, pr_number, branch,
        scanned_at: new Date().toISOString(), summary,
        files_scanned: files.map(f => f.path),
        vulnerabilities: allVulnerabilities
      };

      await s3.send(new PutObjectCommand({
        Bucket: BUCKET_NAME,
        Key: reportKey,
        Body: JSON.stringify(fullReport, null, 2),
        ContentType: 'application/json'
      }));

      // Write SARIF 2.1.0 to S3 (enables GitHub Code Scanning upload and archival)
      const sarifKey = `sarif/${scan_id}.sarif`;
      const sarifDoc = toSarif(fullReport);
      await s3.send(new PutObjectCommand({
        Bucket: BUCKET_NAME,
        Key: sarifKey,
        Body: JSON.stringify(sarifDoc, null, 2),
        ContentType: 'application/sarif+json',
      }));
      console.log(`SARIF written to s3://${BUCKET_NAME}/${sarifKey}`);

      // Upload SARIF to GitHub Code Scanning (best-effort; non-blocking)
      if (GITHUB_TOKEN && repo_name?.includes('/') && branch) {
        uploadSarifToGithub({ repoName: repo_name, branch, sarifDoc, scanId: scan_id })
          .catch(err => console.warn('GitHub SARIF upload failed (non-blocking):', err.message));
      }

      await dynamo.send(new PutItemCommand({
        TableName: TABLE_NAME,
        Item: {
          scan_id:    { S: scan_id },
          scan_type:  { S: 'sast' },
          repo_name:  { S: repo_name },
          severity:   { S: maxSeverity },
          status:     { S: 'completed' },
          scan_scope: { S: isFirstScan ? 'full' : 'diff' },
          ...(appId && { app_id: { S: appId } }),
          pr_number: { N: String(pr_number || 0) },
          total_vulnerabilities: { N: String(summary.totalVulnerabilities) },
          high_count: { N: String(summary.high) },
          medium_count: { N: String(summary.medium) },
          low_count: { N: String(summary.low) },
          files_scanned: { N: String(summary.totalFiles) },
          report_s3_key: { S: reportKey },
          created_at: { S: new Date().toISOString() }
        }
      }));

      // Notify AI analysis pipeline (always, regardless of severity)
      if (SAST_COMPLETE_TOPIC_ARN) {
        await sns.send(new PublishCommand({
          TopicArn: SAST_COMPLETE_TOPIC_ARN,
          Message: JSON.stringify({
            scan_id,
            repo_name,
            app_id: appId,
            report_s3_key: reportKey,
            severity: maxSeverity,
            high_count: summary.high,
            medium_count: summary.medium,
          }),
        }));
      }

      if (SNS_TOPIC_ARN && summary.high > 0) {
        const topHigh = allVulnerabilities
          .filter(v => v.severity === 'HIGH')
          .sort((a, b) => (a.line || 0) - (b.line || 0))
          .slice(0, 5);

        const messageText = [
          `SAST HIGH findings — ${isFirstScan ? 'full repo scan' : 'diff scan'}`,
          `repo: ${repo_name}`,
          `scan_id: ${scan_id}`,
          ...(pr_number ? [`pr: #${pr_number}`] : []),
          `severity: high=${summary.high}, medium=${summary.medium}, low=${summary.low}`,
          `files scanned: ${summary.totalFiles}`,
          ``,
          `Top findings (up to 5):`,
          ...topHigh.map((v, i) =>
            `${i + 1}. [${v.id}] ${v.name} @ ${v.file}:${v.line}\n   ${v.message}${v.evidence ? `\n   evidence: ${v.evidence}` : ''}`
          ),
        ].join('\n');

        await sns.send(new PublishCommand({
          TopicArn: SNS_TOPIC_ARN,
          Subject: `SAST HIGH findings: ${repo_name}`,
          Message: messageText,
        }));
      }

      if (pr_number) {
        try {
          await postPrComment({
            repoName: repo_name,
            prNumber: pr_number,
            summary,
            vulnerabilities: allVulnerabilities,
            scanId: scan_id,
            isFirstScan,
          });
        } catch (commentErr) {
          // Do not fail the entire scan if comment creation fails.
          console.warn("PR comment failed:", commentErr.message);
        }
      }

      const scanDuration = Date.now() - scanStart;
      emitMetric('scans_total',      1,            { scan_type: 'sast', status: 'completed' });
      emitMetric('scan_duration_ms', scanDuration, { scan_type: 'sast' }, 'Milliseconds');

      // Emit findings_total per (language, severity) — enables "findings by language" in Grafana
      const byLangSev = {};
      for (const v of allVulnerabilities) {
        const key = `${v.language ?? 'unknown'}:${v.severity}`;
        byLangSev[key] = (byLangSev[key] ?? 0) + 1;
      }
      for (const [key, count] of Object.entries(byLangSev)) {
        const [language, severity] = key.split(':');
        emitMetric('findings_total', count, { language, severity });
      }

      console.log(`Scan ${scan_id} completed: ${summary.totalVulnerabilities} vulnerabilities found`);
    } catch (err) {
      emitMetric('scans_total', 1, { scan_type: 'sast', status: 'failed' });
      console.error(`Scan ${scan_id} failed:`, err);
      await dynamo.send(new PutItemCommand({
        TableName: TABLE_NAME,
        Item: {
          scan_id: { S: scan_id },
          scan_type: { S: 'sast' },
          repo_name: { S: repo_name },
          severity: { S: 'NONE' },
          status: { S: 'failed' },
          error_message: { S: err.message },
          created_at: { S: new Date().toISOString() }
        }
      }));
      throw err;
    }
  }
};