/**
 * DAST correlation — find recent pentest results for the same app.
 * Called before agent runs so the agent has cross-scan context.
 */
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, GetObjectCommand }    from '@aws-sdk/client-s3';

const dynamo = new DynamoDBClient({});
const s3     = new S3Client({});

const SCANS_TABLE  = process.env.SCANS_TABLE_NAME;
const BUCKET       = process.env.REPORTS_BUCKET_NAME;
const SEVEN_DAYS   = 7 * 24 * 60 * 60 * 1000;

async function streamToString(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf-8');
}

/**
 * Returns a DAST context object for the given app, or null if none found.
 * Only looks at completed pentest scans within the last 7 days.
 */
export async function getDastContext(appId) {
  if (!appId || !SCANS_TABLE) return null;

  const cutoff = new Date(Date.now() - SEVEN_DAYS).toISOString();

  try {
    const result = await dynamo.send(new QueryCommand({
      TableName:                 SCANS_TABLE,
      IndexName:                 'app-time-index',
      KeyConditionExpression:    'app_id = :app AND created_at > :cutoff',
      FilterExpression:          'scan_type = :t AND #s = :done',
      ExpressionAttributeNames:  { '#s': 'status' },
      ExpressionAttributeValues: {
        ':app':    { S: appId },
        ':cutoff': { S: cutoff },
        ':t':      { S: 'pentest' },
        ':done':   { S: 'completed' },
      },
      ScanIndexForward: false,
      Limit: 1,
    }));

    const recentScan = result.Items?.[0];
    if (!recentScan) return null;

    const s3Key = recentScan.report_s3_key?.S;
    if (!s3Key) return null;

    const obj  = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: s3Key }));
    const text = await streamToString(obj.Body);
    const report = JSON.parse(text);

    // Only keep FAIL results (actual vulnerabilities found), capped at 10
    const failures = (report.results ?? [])
      .filter(r => r.status === 'FAIL')
      .slice(0, 10)
      .map(r => ({
        test_type: r.test_type,
        endpoint:  r.endpoint,
        method:    r.method,
        evidence:  r.evidence,
      }));

    return {
      pentest_scan_id: recentScan.scan_id?.S,
      scanned_at:      recentScan.created_at?.S,
      target_url:      recentScan.target_url?.S ?? report.target_url,
      failures,
      endpoints_discovered: report.endpoints_discovered?.length ?? 0,
    };
  } catch (err) {
    console.warn(`getDastContext(${appId}) failed:`, err.message);
    return null;
  }
}
