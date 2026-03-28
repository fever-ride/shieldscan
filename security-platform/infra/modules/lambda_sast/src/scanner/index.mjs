/**
 * SAST Scanner Lambda
 * Triggered by SQS → fetches code from GitHub → runs scanCode() → writes DynamoDB + S3
 */
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { scanCode } from './scanner.mjs';

const dynamo = new DynamoDBClient({});
const s3 = new S3Client({});
const sns = new SNSClient({});

const TABLE_NAME = process.env.SCANS_TABLE_NAME;
const BUCKET_NAME = process.env.REPORTS_BUCKET_NAME;
const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

async function postPrComment({ repoName, prNumber, summary, vulnerabilities, reportKey, scanId }) {
  if (!GITHUB_TOKEN || !repoName || !prNumber) return;
  if (!repoName.includes("/")) return;

  const [owner, repo] = repoName.split("/");
  const topFindings = vulnerabilities.slice(0, 5);

  const findingLines = topFindings.length
    ? topFindings.map(
        (v) => `- [${v.severity}] ${v.name} in \`${v.file}\` (line ${v.line})`
      )
    : ["- No vulnerabilities detected in sampled files."];

  const body = [
    "## Security Scan Result",
    "",
    `- Scan ID: \`${scanId}\``,
    `- Files scanned: ${summary.totalFiles}`,
    `- Total findings: ${summary.totalVulnerabilities}`,
    `- High: ${summary.high} | Medium: ${summary.medium} | Low: ${summary.low}`,
    `- Full report: \`s3://${BUCKET_NAME}/${reportKey}\``,
    "",
    "### Top Findings",
    ...findingLines,
  ].join("\n");

  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "security-platform-sast",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body }),
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`PR comment failed (${res.status}): ${text}`);
  }
}

async function fetchCodeFromGithub(cloneUrl, branch, repo) {
  const apiBase = `https://api.github.com/repos/${repo}`;
  const headers = GITHUB_TOKEN
    ? { Authorization: `Bearer ${GITHUB_TOKEN}`, 'User-Agent': 'sast-scanner' }
    : { 'User-Agent': 'sast-scanner' };

  const treeRes = await fetch(`${apiBase}/git/trees/${branch}?recursive=1`, { headers });
  if (!treeRes.ok) throw new Error(`GitHub API error: ${treeRes.status}`);
  const tree = await treeRes.json();

  const jsFiles = tree.tree.filter(f =>
    f.type === 'blob' &&
    /\.(js|mjs|cjs)$/.test(f.path) &&
    !f.path.includes('node_modules') &&
    !f.path.includes('dist/') &&
    !f.path.includes('.min.')
  );

  const files = [];
  for (const file of jsFiles.slice(0, 50)) {
    try {
      const contentRes = await fetch(`${apiBase}/contents/${file.path}?ref=${branch}`, { headers });
      if (!contentRes.ok) continue;
      const contentData = await contentRes.json();
      const code = Buffer.from(contentData.content, 'base64').toString('utf-8');
      files.push({ path: file.path, code });
    } catch (e) {
      console.warn(`Failed to fetch ${file.path}:`, e.message);
    }
  }

  return files;
}

export const handler = async (event) => {
  for (const record of event.Records) {
    const job = JSON.parse(record.body);
    const { scan_id, repo_name, pr_number, branch, clone_url } = job;

    console.log(`Processing SAST scan: ${scan_id} for ${repo_name}`);

    try {
      const files = await fetchCodeFromGithub(clone_url, branch, repo_name);

      const allVulnerabilities = [];
      for (const file of files) {
        const vulns = scanCode(file.code, file.path);
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

      await dynamo.send(new PutItemCommand({
        TableName: TABLE_NAME,
        Item: {
          scan_id: { S: scan_id },
          scan_type: { S: 'sast' },
          repo_name: { S: repo_name },
          severity: { S: maxSeverity },
          status: { S: 'completed' },
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

      if (SNS_TOPIC_ARN && summary.high > 0) {
        await sns.send(new PublishCommand({
          TopicArn: SNS_TOPIC_ARN,
          Subject: `🚨 SAST Alert: ${summary.high} HIGH severity findings in ${repo_name}`,
          Message: JSON.stringify({
            scan_id, repo: repo_name, pr: pr_number,
            high: summary.high, medium: summary.medium, low: summary.low,
            report: `s3://${BUCKET_NAME}/${reportKey}`
          }, null, 2)
        }));
      }

      if (pr_number) {
        try {
          await postPrComment({
            repoName: repo_name,
            prNumber: pr_number,
            summary,
            vulnerabilities: allVulnerabilities,
            reportKey,
            scanId: scan_id,
          });
        } catch (commentErr) {
          // Do not fail the entire scan if comment creation fails.
          console.warn("PR comment failed:", commentErr.message);
        }
      }

      console.log(`Scan ${scan_id} completed: ${summary.totalVulnerabilities} vulnerabilities found`);
    } catch (err) {
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