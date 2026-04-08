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
import { emitMetric } from './emf.mjs';

const dynamo = new DynamoDBClient({});
const s3 = new S3Client({});

const SCANS_TABLE       = process.env.SCANS_TABLE_NAME;
const APPS_TABLE        = process.env.APPS_TABLE_NAME;
const AI_FEEDBACK_TABLE = process.env.AI_FEEDBACK_TABLE_NAME;
const BUCKET            = process.env.REPORTS_BUCKET_NAME;

function response(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body)
  };
}

async function listScans(params) {
  const { scan_type, repo_name, severity, app_id, limit = '20' } = params;

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

  if (app_id) {
    const result = await dynamo.send(new QueryCommand({
      TableName: SCANS_TABLE,
      IndexName: 'app-time-index',
      KeyConditionExpression: 'app_id = :app',
      ExpressionAttributeValues: { ':app': { S: app_id } },
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

async function listApps(owner) {
  if (owner) {
    const result = await dynamo.send(new QueryCommand({
      TableName: APPS_TABLE,
      IndexName: 'owner-index',
      KeyConditionExpression: '#o = :owner',
      ExpressionAttributeNames: { '#o': 'owner' },
      ExpressionAttributeValues: { ':owner': { S: owner } },
      ScanIndexForward: false,
    }));
    return result.Items;
  }
  const result = await dynamo.send(new ScanCommand({ TableName: APPS_TABLE }));
  return result.Items;
}

async function addApp(body) {
  const {
    repo_name, target_url, app_name, owner, schedule, team,
    // Auth config — canonical keys match tester.authenticate()
    auth_config,
    // Endpoint resolution
    openapi_url, endpoint_list, use_manual_override,
  } = body;

  if (!target_url) throw new Error('target_url required');

  const appId = randomUUID();

  const item = {
    app_id:     { S: appId },
    app_name:   { S: app_name  || 'unnamed' },
    target_url: { S: target_url },
    owner:      { S: owner     || 'default' },
    schedule:   { S: schedule  || 'manual_only' },
    team:       { S: team      || 'default' },
    created_at: { S: new Date().toISOString() },
  };

  if (repo_name) item.repo_name = { S: repo_name };

  // Auth config — stored flat; trigger/index.mjs remaps to canonical keys for SQS jobs
  if (auth_config?.type) {
    item.auth_type = { S: auth_config.type };
    if (auth_config.token)       item.auth_token       = { S: auth_config.token };
    if (auth_config.login_url)   item.auth_login_url   = { S: auth_config.login_url };
    if (auth_config.credentials) item.auth_credentials = { S: JSON.stringify(auth_config.credentials) };
    if (auth_config.token_path)  item.auth_token_path  = { S: auth_config.token_path };
  }

  if (openapi_url)                  item.openapi_url         = { S: openapi_url };
  if (endpoint_list?.length)        item.endpoint_list       = { S: JSON.stringify(endpoint_list) };
  if (use_manual_override === true) item.use_manual_override = { BOOL: true };

  await dynamo.send(new PutItemCommand({ TableName: APPS_TABLE, Item: item }));
  return { app_id: appId };
}

/** Returns a presigned URL for the agent investigation report at ai/agent/{scan_id}.json */
async function getAgentReport(scanId) {
  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key:    `ai/agent/${scanId}.json`,
  });
  const url = await getSignedUrl(s3, command, { expiresIn: 900 });
  return { agent_url: url, scan_id: scanId, expires_in: 900 };
}

/** Returns a presigned URL for the AI triage report at ai/{scan_id}.json */
async function getTriage(scanId) {
  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key:    `ai/${scanId}.json`,
  });
  const url = await getSignedUrl(s3, command, { expiresIn: 900 });
  return { triage_url: url, scan_id: scanId, expires_in: 900 };
}

/** Writes a human-review decision to the ai_feedback table. */
async function addFeedback(body, owner) {
  const { scan_id, finding_id, action } = body; // action: 'confirm' | 'dismiss'
  if (!scan_id || !finding_id || !['confirm', 'dismiss'].includes(action)) {
    throw new Error('scan_id, finding_id, and action (confirm|dismiss) are required');
  }
  const feedbackId = randomUUID();
  await dynamo.send(new PutItemCommand({
    TableName: AI_FEEDBACK_TABLE,
    Item: {
      feedback_id: { S: feedbackId },
      scan_id:     { S: scan_id },
      finding_id:  { S: finding_id },
      action:      { S: action },
      owner:       { S: owner || 'unknown' },
      created_at:  { S: new Date().toISOString() },
    },
  }));
  return { feedback_id: feedbackId };
}

/** Returns all human feedback records for a scan, keyed by finding_id. */
async function getFeedback(scanId) {
  // ai_feedback has no scan_id GSI; scan count per scan_id is small so Scan + filter is fine
  const result = await dynamo.send(new ScanCommand({
    TableName: AI_FEEDBACK_TABLE,
    FilterExpression: 'scan_id = :s',
    ExpressionAttributeValues: { ':s': { S: scanId } },
  }));
  // Return { [finding_id]: 'confirm' | 'dismiss' } — sort by created_at, last action wins
  const sorted = (result.Items ?? []).sort((a, b) =>
    (a.created_at?.S ?? '').localeCompare(b.created_at?.S ?? '')
  );
  const byFinding = {};
  for (const item of sorted) {
    const fid    = item.finding_id?.S;
    const action = item.action?.S;
    if (fid && action) byFinding[fid] = action;
  }
  return byFinding;
}

/** Extract the caller's identity from the Cognito JWT claims injected by API Gateway. */
function callerEmail(event) {
  return event.requestContext?.authorizer?.jwt?.claims?.email || null;
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

    if (route === 'GET /apps') {
      // owner is taken from the JWT, not the query string
      const owner = callerEmail(event);
      const items = await listApps(owner);
      return response(200, { count: items.length, apps: items });
    }

    if (route === 'POST /apps') {
      const body = JSON.parse(event.body || '{}');
      // Stamp the app with the caller's identity; ignore any owner in the body
      body.owner = callerEmail(event) || body.owner;
      const result = await addApp(body);
      return response(201, result);
    }

    if (route.startsWith('GET /agent/')) {
      const scanId = event.pathParameters?.id;
      if (!scanId) return response(400, { error: 'scan_id required' });
      try {
        const result = await getAgentReport(scanId);
        return response(200, result);
      } catch {
        return response(404, { error: 'Agent report not found' });
      }
    }

    if (route.startsWith('GET /triage/')) {
      const scanId = event.pathParameters?.id;
      if (!scanId) return response(400, { error: 'scan_id required' });
      try {
        const result = await getTriage(scanId);
        return response(200, result);
      } catch (e) {
        return response(404, { error: 'Triage report not found' });
      }
    }

    if (route.startsWith('GET /ai-feedback/')) {
      const scanId = event.pathParameters?.id;
      if (!scanId) return response(400, { error: 'scan_id required' });
      const feedback = await getFeedback(scanId);
      return response(200, { scan_id: scanId, feedback });
    }

    if (route === 'POST /ai-feedback') {
      const body  = JSON.parse(event.body || '{}');
      const owner = callerEmail(event);
      const result = await addFeedback(body, owner);
      emitMetric('human_feedback_total', 1, { action: body.action ?? 'unknown' });
      return response(201, result);
    }

    return response(404, { error: 'Route not found', route });
  } catch (err) {
    console.error('Query API error:', err);
    return response(500, { error: err.message });
  }
};