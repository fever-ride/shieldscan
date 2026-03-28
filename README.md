# ShieldScan

A cloud-native Static Application Security Testing (SAST) platform that automatically scans code on every GitHub pull request and push, reports findings to a dashboard, and alerts on high-severity vulnerabilities.

## How it works

1. A GitHub webhook fires on PR / push events
2. A validator Lambda authenticates the webhook and queues a scan job via SQS
3. A scanner Lambda fetches the changed files from GitHub, runs static analysis, and stores the report in S3 + DynamoDB
4. The dashboard (React + CloudFront) lets you browse scan history and findings
5. SNS sends alerts when HIGH severity issues are found

## Repository structure

```
platform/          Core platform — infra (Terraform), frontend dashboard, Lambda source code, pentest worker
demo/              Demo vulnerable app with a pre-configured webhook workflow for end-to-end testing
```

## Stack

AWS Lambda · SQS · DynamoDB · S3 · SNS · CloudFront · Cognito · Terraform · React
