/**
 * Query API Lambda
 * Handles all dashboard read/write requests via API Gateway
 *
 * Routes (determined by event.routeKey):
 *   GET  /scans          → list scans (with filters)
 *   GET  /reports/{id}   → get pre-signed S3 URL for full report
 *   GET  /targets        → list pentest targets
 *   POST /targets        → add/update a pentest target
 */
import { DynamoDBClient, QueryCommand, ScanCommand, PutItemCommand, DeleteItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomUUID } from 'crypto';

const dynamo = new DynamoDBClient({});
const s3 = new S3Client({});

const SCANS_TABLE = process.env.SCANS_TABLE_NAME;
const TARGETS_TABLE = process.env.SCAN_TARGETS_TABLE_NAME;
const BUCKET = process.env.REPORTS_BUCKET_NAME;

function response(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body)
  };
}

async function listScans(params) {
  const { scan_type, repo_name, severity, limit = '20' } = params;

  if (repo_name) {
    const result = await dynamo.send(new QueryCommand({
      TableName: SCANS_TABLE,
      IndexName: 'repo-time-index',
      KeyConditionExpression: 'repo_name = :repo',
      ExpressionAttributeValues: { ':repo': { S: repo_name } },
      ScanIndexForward: false,
      Limit: parseInt(limit)
    }));
    return result.Items;
  }

  if (scan_type) {
    const result = await dynamo.send(new QueryCommand({
      TableName: SCANS_TABLE,
      IndexName: 'type-time-index',
      KeyConditionExpression: 'scan_type = :type',
      ExpressionAttributeValues: { ':type': { S: scan_type } },
      ScanIndexForward: false,
      Limit: parseInt(limit)
    }));
    return result.Items;
  }

  if (severity) {
    const result = await dynamo.send(new QueryCommand({
      TableName: SCANS_TABLE,
      IndexName: 'severity-time-index',
      KeyConditionExpression: 'severity = :sev',
      ExpressionAttributeValues: { ':sev': { S: severity } },
      ScanIndexForward: false,
      Limit: parseInt(limit)
    }));
    return result.Items;
  }

  const result = await dynamo.send(new ScanCommand({
    TableName: SCANS_TABLE,
    Limit: parseInt(limit)
  }));
  return result.Items;
}

async function getReport(scanId) {
  const item = await dynamo.send(new GetItemCommand({
    TableName: SCANS_TABLE,
    Key: { scan_id: { S: scanId } }
  }));

  if (!item.Item?.report_s3_key?.S) {
    return null;
  }

  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key: item.Item.report_s3_key.S
  });
  const expiresInSeconds = 900;
  const reportUrl = await getSignedUrl(s3, command, { expiresIn: expiresInSeconds });

  return {
    report_url: reportUrl,
    report_s3_key: item.Item.report_s3_key.S,
    expires_in: expiresInSeconds
  };
}

async function listTargets() {
  const result = await dynamo.send(new ScanCommand({ TableName: TARGETS_TABLE }));
  return result.Items;
}

async function addTarget(body) {
  const { target_url, app_name, schedule, team } = body;
  if (!target_url) throw new Error('target_url required');

  const targetId = randomUUID();
  await dynamo.send(new PutItemCommand({
    TableName: TARGETS_TABLE,
    Item: {
      target_id: { S: targetId },
      target_url: { S: target_url },
      app_name: { S: app_name || 'unnamed' },
      schedule: { S: schedule || 'manual_only' },
      team: { S: team || 'default' },
      created_at: { S: new Date().toISOString() }
    }
  }));
  return { target_id: targetId };
}

export const handler = async (event) => {
  const route = event.routeKey || `${event.httpMethod} ${event.path}`;
  const params = event.queryStringParameters || {};

  try {
    if (route === 'GET /scans') {
      const items = await listScans(params);
      return response(200, { count: items.length, scans: items });
    }

    if (route.startsWith('GET /reports/')) {
      const scanId = event.pathParameters?.id;
      const report = await getReport(scanId);
      if (!report) return response(404, { error: 'Report not found' });
      return response(200, report);
    }

    if (route === 'GET /targets') {
      const items = await listTargets();
      return response(200, { count: items.length, targets: items });
    }

    if (route === 'POST /targets') {
      const body = JSON.parse(event.body || '{}');
      const result = await addTarget(body);
      return response(201, result);
    }

    return response(404, { error: 'Route not found', route });
  } catch (err) {
    console.error('Query API error:', err);
    return response(500, { error: err.message });
  }
};