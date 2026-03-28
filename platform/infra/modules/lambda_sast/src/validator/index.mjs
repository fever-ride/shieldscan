/**
 * Lambda: SAST Webhook Validator
 * 
 * Receives GitHub webhook from API Gateway
 * → Validates HMAC signature
 * → Extracts repo/PR info
 * → Pushes scan job to SQS
 */

import crypto from 'crypto';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';

const sqs = new SQSClient({});
const SAST_QUEUE_URL = process.env.SAST_QUEUE_URL;
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

// Verify GitHub webhook HMAC-SHA256 signature
function verifySignature(payload, signature) {
  if (!GITHUB_WEBHOOK_SECRET || !signature) return false;

  const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(payload).digest('hex');
  
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch {
    return false;
  }
}

export const handler = async (event) => {
  try {
    const body = event.body || '';
    const signature = event.headers?.['x-hub-signature-256'] || '';

    // Verify webhook signature
    if (GITHUB_WEBHOOK_SECRET && !verifySignature(body, signature)) {
      console.error('Invalid webhook signature');
      return { statusCode: 401, body: JSON.stringify({ error: 'Invalid signature' }) };
    }

    const payload = JSON.parse(body);

    // Only process pull_request and push events
    const githubEvent = event.headers?.['x-github-event'] || '';
    if (!['pull_request', 'push'].includes(githubEvent)) {
      return { statusCode: 200, body: JSON.stringify({ message: 'Event ignored', event: githubEvent }) };
    }

    // Extract repo and PR info
    const repo = payload.repository?.full_name || 'unknown/repo';
    const prNumber = payload.pull_request?.number || null;
    const branch = payload.pull_request?.head?.ref || payload.ref || 'unknown';
    const commitSha = payload.pull_request?.head?.sha || payload.after || 'unknown';
    const cloneUrl = payload.repository?.clone_url || '';

    // Build scan job message
    const scanJob = {
      scan_id: crypto.randomUUID(),
      scan_type: 'sast',
      repo_name: repo,
      pr_number: prNumber,
      branch,
      commit_sha: commitSha,
      clone_url: cloneUrl,
      triggered_at: new Date().toISOString(),
    };

    // Push to SQS
    await sqs.send(new SendMessageCommand({
      QueueUrl: SAST_QUEUE_URL,
      MessageBody: JSON.stringify(scanJob),
    }));

    console.log(`Scan job queued: ${scanJob.scan_id} for ${repo} PR#${prNumber}`);

    return {
      statusCode: 200,
      body: JSON.stringify({ 
        message: 'Scan job queued',
        scan_id: scanJob.scan_id,
        repo: repo,
        pr: prNumber,
      }),
    };
  } catch (error) {
    console.error('Validator error:', error);
    return { statusCode: 500, body: JSON.stringify({ error: 'Internal error' }) };
  }
};