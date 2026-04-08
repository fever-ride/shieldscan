# ShieldScan

ShieldScan is a cloud-native application security platform that combines static code analysis (SAST), dynamic penetration testing (DAST), and an AI advisory layer. It scans codebases on every GitHub pull request, runs automated security tests against live endpoints, and surfaces findings through a React dashboard with AI-assisted triage.

The platform is designed for small security teams and individual developers who want a single workflow to go from raw findings to actionable, prioritized results. All AI outputs are suggestions that require human confirmation before any finding status changes.

---

## Table of Contents

- [Architecture](#architecture)
- [SAST Engine](#sast-engine)
- [DAST Engine](#dast-engine)
- [AI Advisory Layer](#ai-advisory-layer)
- [Observability](#observability)
- [API Routes](#api-routes)
- [Dashboard](#dashboard)
- [AI Triage Evaluation](#ai-triage-evaluation)
- [Infrastructure](#infrastructure)
- [Configuration](#configuration)
- [Repository Layout](#repository-layout)

---

## Architecture

### Data flow

```
GitHub Webhook (PR / push)
        │
        ▼
API Gateway ──► POST /webhook/sast
        │
        ▼
Lambda: Validator
  • Verifies HMAC-SHA256 signature
  • Publishes job to SQS (sast-queue)
        │
        ▼
Lambda: Scanner
  • Fetches up to 100 source files via GitHub API
  • Runs multi-language SAST rules
  • Writes JSON report    → S3  sast/{scan_id}.json
  • Writes SARIF 2.1.0   → S3  sarif/{scan_id}.sarif
  • Writes scan summary  → DynamoDB (scans table)
  • Publishes to SNS     → sast-complete topic
  • (Optional) uploads SARIF → GitHub Code Scanning API
        │
        ├──────────────────────────────────────────────────────────────────┐
        ▼                                                                  ▼
API Gateway ──► POST /scan/pentest                               SNS: sast-complete
        │                                                                  │
        ▼                                                                  ▼
Lambda: Pentest Trigger                                         Lambda: AI Analysis
  • Validates request                                             (AI_ANALYSIS_ENABLED=true)
  • Publishes job to SQS (pentest-queue)                                   │
        │                                              ┌────────────────────┤
        ▼                                              │                   │
ECS Fargate: Pentest Worker                            ▼                   ▼
  • Polls SQS (long-poll, 20s)             Phase 1: Triage            Phase 2: Agent
  • Resolves endpoints                      (claude-haiku)             (claude-sonnet)
    OpenAPI spec → manual list              • Batches top-20            • Top-3 HIGH findings
    → common-path probe                       HIGH/MEDIUM findings      • ReAct loop
  • Runs 8 security test types             • Assigns label:              max 10 tool calls
  • Writes JSON report → S3                  TRUE_POSITIVE               3-min timeout
  • Writes summary → DynamoDB               FALSE_POSITIVE             • GitHub API tools
  • Publishes FAIL alerts → SNS             NEEDS_REVIEW               • Issues verdict:
                                          • Writes ai/{scan_id}.json     CONFIRMED
                                                                         LIKELY_FALSE_POSITIVE
                                                                         INCONCLUSIVE
                                                                       • Writes ai/agent/{scan_id}.json
                                                                       • Emits EMF metrics

All scans (SAST + DAST + AI) ──► DynamoDB (scans, apps, ai_feedback tables)

React Dashboard ──► API Gateway ──► Lambda: Query API
  • Browse scan history                   • Serves pre-signed S3 URLs
  • View AI suggestions                   • Reads DynamoDB
  • Confirm / Dismiss findings            • Writes human feedback
  • Register apps (repo + target URL)     • Emits EMF: human_feedback_total
  (Cognito JWT auth)
```

### Component responsibilities

| Component | Runtime | Trigger | Key output |
|-----------|---------|---------|-----------|
| Validator Lambda | Node 18 | API Gateway | SQS message |
| Scanner Lambda | Node 18 | SQS | S3 JSON + SARIF, DynamoDB, SNS |
| Pentest Trigger Lambda | Node 18 | API Gateway | SQS message |
| Pentest Worker | Node 18, ECS Fargate | SQS | S3 JSON, DynamoDB, SNS |
| AI Analysis Lambda | Node 18 | SNS | S3 triage + agent JSON, DynamoDB |
| Query API Lambda | Node 18 | API Gateway | JSON responses, pre-signed URLs |
| Alert Lambda | Node 18 | SNS | Email (via SNS) |

---

## SAST Engine

### Scan scope

On the first scan of a repository, the scanner fetches up to 100 source files across the full tree. On subsequent scans triggered by a pull request, it fetches only the files changed in that PR diff. This reduces token usage and keeps scan time proportional to the change size.

Files are prioritized by directory before the 100-file cap is applied. Directories like `routes/`, `controllers/`, `auth/`, `middleware/`, and `api/` are fetched first because they are higher-risk surfaces.

Test files (`*.test.js`, `__tests__/`, `/fixtures/`) and build artifacts (`dist/`, `node_modules/`, `.min.js`) are excluded.

### Rule architecture

Rules are organized by language and composed at scan time. Each file is detected by extension, then scanned against the common rules plus the language-specific rule set.

```
scanCode(code, filename)
        │
        ├── detectLanguage(filename)   (.js/.ts → javascript, .py → python, etc.)
        │
        ├── COMMON_RULES               applied to every language
        │     • HARDCODED_SECRET       API keys, passwords, AWS credentials, GitHub tokens, Stripe keys
        │     • HARDCODED_IP           Production IP addresses hardcoded in source
        │
        └── LANGUAGE_RULES             applied only to matched language
              • JS_RULES, PY_RULES, JAVA_RULES, GO_RULES
```

### Rules by language

**Common (all languages)**

| Rule ID | Severity | What it detects |
|---------|----------|----------------|
| `HARDCODED_SECRET` | HIGH | API keys, passwords, AWS keys, GitHub PATs, Stripe live keys |
| `HARDCODED_IP` | MEDIUM | IPv4 addresses hardcoded in source |

**JavaScript / TypeScript**

| Rule ID | Severity | What it detects |
|---------|----------|----------------|
| `SQL_INJECTION` | HIGH | String concatenation and template literals in `query()` / `execute()` |
| `NOSQL_INJECTION` | HIGH | User input (`req.body`, `req.query`, `req.params`) passed directly to MongoDB `find()`, `findOne()`, `updateOne()`, `deleteOne()` |
| `XSS` | HIGH | `innerHTML`, `outerHTML`, `document.write()`, `insertAdjacentHTML()`, `dangerouslySetInnerHTML` |
| `PATH_TRAVERSAL` | HIGH | User input in `fs.readFile`, `fs.writeFile`, `path.join()` |
| `INSECURE_FUNCTION` | HIGH | `eval()`, `execSync()`, `new Function()`, `child_process.exec` |
| `JWT_MISUSE` | HIGH | `jwt.decode()` without verify, `jwt.verify()` with null secret, `alg: "none"` |
| `PROTOTYPE_POLLUTION` | HIGH | `Object.assign()` with user input, spread of `req.body` |
| `WEAK_CRYPTO` | MEDIUM | MD5, SHA-1, deprecated `createCipher()` |
| `INSECURE_RANDOM` | MEDIUM | `Math.random()` used in security-sensitive context (token, password, session, key) |
| `SENSITIVE_DATA_LOG` | MEDIUM | `console.log()` containing `.password`, `.token`, `.apiKey`, credit card fields |
| `CORS_MISCONFIGURATION` | MEDIUM | Wildcard origin `*` in `cors()` config or response headers |

**Python**

| Rule ID | Severity | What it detects |
|---------|----------|----------------|
| `SQL_INJECTION` | HIGH | f-string or `%` formatting in `execute()`, string concatenation in queries |
| `XSS` | HIGH | Jinja2 `\|safe`, Flask `Markup()`, Django `mark_safe()` |
| `PATH_TRAVERSAL` | HIGH | User input in `open()`, `os.path.join()` |
| `INSECURE_FUNCTION` | HIGH | `eval()`, `exec()`, `pickle.loads()`, `os.system()`, `yaml.load()` without safe loader |
| `WEAK_CRYPTO` | MEDIUM | MD5, SHA-1, DES, RC4, RC2, Blowfish |
| `INSECURE_RANDOM` | MEDIUM | `random.random()`, `random.randint()`, `random.choice()` |
| `SENSITIVE_DATA_LOG` | MEDIUM | Logging password, token, or secret values |

**Java**

| Rule ID | Severity | What it detects |
|---------|----------|----------------|
| `SQL_INJECTION` | HIGH | String concatenation in JDBC `execute()`, `executeQuery()` |
| `XSS` | HIGH | `response.getWriter()` with unsanitized `getParameter()` |
| `PATH_TRAVERSAL` | HIGH | User input in `File()`, `FileInputStream()`, `Paths.get()` |
| `INSECURE_DESERIALIZE` | HIGH | `ObjectInputStream`, `readObject()`, `XMLDecoder` |
| `INSECURE_FUNCTION` | HIGH | `Runtime.exec()`, `ProcessBuilder` with user input |
| `WEAK_CRYPTO` | MEDIUM | MD5, SHA-1, DES ciphers |

**Go**

| Rule ID | Severity | What it detects |
|---------|----------|----------------|
| `SQL_INJECTION` | HIGH | `fmt.Sprintf()` or string concatenation in `db.Query()` |
| `PATH_TRAVERSAL` | HIGH | User input in `http.ServeFile()`, `os.Open()`, `filepath.Join()` |
| `INSECURE_FUNCTION` | HIGH | `exec.Command()` with user-controlled arguments |
| `WEAK_CRYPTO` | MEDIUM | `md5.New()`, `sha1.New()` |
| `INSECURE_RANDOM` | MEDIUM | `math/rand` instead of `crypto/rand` |

### Deduplication and stable IDs

After scanning, findings are deduplicated on `(rule_id, file, line)`. Each surviving finding gets a stable `finding_id` in the format `RULE_ID:path/to/file.js:42`. This ID is used as the feedback key in the `ai_feedback` DynamoDB table, so human confirm/dismiss decisions are always tied to a specific location in code.

### SARIF output

The scanner serializes every completed scan to SARIF 2.1.0 and writes it to `sarif/{scan_id}.sarif` in S3. It then attempts to upload the SARIF to the GitHub Code Scanning API using the commit SHA of the scanned branch. A GitHub Actions workflow (`sarif-upload.yml`) is also provided as a manual fallback for cases where the Lambda upload is blocked by token scope.

---

## DAST Engine

The pentest worker runs inside an ECS Fargate container. It polls an SQS queue and processes one job at a time. Each job specifies a `target_url`, optional auth configuration, and optional endpoint hints.

### Endpoint resolution

Before running any tests, the worker resolves which endpoints to test. It follows a priority order:

```
1. use_manual_override = true + endpoint_list  →  use the provided list, skip OpenAPI
2. openapi_url provided                        →  fetch spec, parse all paths and methods
3. endpoint_list provided (no override)        →  use the list as-is
4. fallback                                    →  probe 16 common paths (/, /api, /health, etc.)
```

Endpoints discovered from OpenAPI have path parameters like `{id}` replaced with `1` so they are immediately requestable.

### Authentication modes

| Mode | Config | Behavior |
|------|--------|---------|
| `bearer` | `{ type: "bearer", token: "eyJ..." }` | Injects `Authorization: Bearer <token>` on every request |
| `login` | `{ type: "login", login_url, credentials, token_path }` | POSTs credentials to login URL, extracts token from response using dot-notation path (e.g. `data.token`) |
| none | omitted | Tests run without auth headers |

### Security tests

| Test ID | Severity | Method |
|---------|----------|--------|
| `AUTH_MISSING` | HIGH | Requests endpoints without auth headers; flags 200 responses with substantial body as potentially unauthenticated |
| `SQL_INJECTION` | HIGH | Injects 5 payloads via GET query params and POST body. Requires 2+ distinct signals (error keywords, status change, response size diff) for HIGH confidence. Single signal produces WARNING |
| `NOSQL_INJECTION` | HIGH | Injects MongoDB operators (`$gt`, `$ne`, `$where`, `$regex`) into POST body. Detects auth bypass, DB error leakage, data leak, and response size increase |
| `CORS_MISCONFIGURATION` | MEDIUM | Sends `Origin: https://evil.shieldscan-test.example.com` header; flags if response reflects the origin or returns `*` |
| `RATE_LIMITING` | MEDIUM | Fires 20 concurrent requests at auth/payment endpoint candidates; flags if all succeed with no 429 response |
| `SECURITY_HEADERS` | MEDIUM | Checks for `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`; flags missing or misconfigured headers and leaking `Server`/`X-Powered-By` headers |
| `SENSITIVE_DATA_EXPOSURE` | HIGH | Scans GET responses and verbose error responses for passwords, API keys, stack traces, and DB connection strings |
| `OPEN_REDIRECT` | MEDIUM | Probes 11 common redirect parameters (`next`, `url`, `redirect`, `returnTo`, `continue`, `dest`, etc.). Uses `redirect: manual` to intercept the Location header without following the redirect. Requires 2+ parameters to confirm FAIL; single match produces WARNING |

All tests record `endpoints_tested[]` in their result object. The pentest report written to S3 includes `endpoints_discovered` as structured objects `{ url, path, method, source }` rather than plain strings.

---

## AI Advisory Layer

### Design principle

The AI layer is strictly advisory. It produces labels and verdicts with confidence scores and reasoning, but it cannot change finding severity or dismiss a finding autonomously. Every AI output in the dashboard is labelled "AI Suggestion — requires human review." A human must click Confirm or Dismiss in the dashboard to record a decision.

This matches how production security tools like Snyk and GitHub GHAS work, and it avoids the class of errors that come from trusting automated systems to make irreversible security decisions.

### Phase 1: Batch triage

The triage step runs once per scan, shortly after SAST completes. It sends the top 20 findings (sorted by severity) to Claude Haiku in a single API call and receives a structured JSON response.

Each finding in the triage output has:

| Field | Type | Description |
|-------|------|-------------|
| `finding_id` | string | Matches the stable SAST finding ID |
| `label` | enum | `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_REVIEW` |
| `confidence` | float | 0.0 to 1.0 |
| `reasoning` | string | 1-2 sentence explanation |
| `remediation` | string | Specific fix suggestion (empty for FP) |

The triage prompt includes the `±5-line code context` extracted from the source file during scanning. This gives the model the same contextual information a human reviewer would have.

Output is written to `ai/{scan_id}.json` in S3 and summary counts are written back to the DynamoDB scan record.

### Phase 2: Deep investigation agent

After triage, the agent investigates the top 3 HIGH findings using a ReAct loop. It uses `claude-sonnet-4-6` and has access to three GitHub API tools.

**Agent tools**

| Tool | Description |
|------|-------------|
| `get_file_context` | Fetches a range of lines from a file at a specific branch or commit SHA. Parameters: `repo`, `path`, `ref`, `start_line`, `end_line` |
| `search_code` | Searches for a keyword or symbol across the repository using GitHub code search. Returns up to 5 matching files with paths. Note: operates on the default branch only |
| `get_directory_tree` | Lists files in a directory at a given ref. Useful for understanding project structure and locating middleware or route files |

**Agent loop**

```
Input: finding (finding_id, rule, file, line, code context, DAST context if available)

Loop (max 10 tool calls, 3-minute wall-clock timeout):
  ├── Model generates reasoning step
  ├── If tool_use block: execute tool → append result → continue
  └── If end_turn or no more tool calls: attempt to extract structured verdict

Structured output extraction:
  1. Parse JSON from model response
  2. Validate verdict against whitelist: CONFIRMED | LIKELY_FALSE_POSITIVE | INCONCLUSIVE
  3. If validation fails: one schema-retry turn with explicit JSON format instruction
  4. If still invalid: record validation_error in output

Output per finding:
  { finding_id, verdict, confidence, attack_path, remediation, investigation_trace, tool_calls_used }
```

**SAST × DAST correlation**

If the same `app_id` has a completed pentest scan within the last 7 days, the agent receives a `dast_context` block alongside the SAST finding. This context includes the target URL, failed test IDs, and up to 10 DAST failure details. The agent can then reason across both scan types: for example, a SQL injection finding in `src/user.js` combined with a SQL error response on `/api/user` strengthens the case for a confirmed true positive.

The agent output is written to `ai/agent/{scan_id}.json` in S3. Verdict counts are written back to DynamoDB.

### Human feedback loop

```
Dashboard
   │
   ├── GET /triage/{scan_id}          → pre-signed S3 URL for triage JSON
   ├── GET /agent/{scan_id}           → pre-signed S3 URL for agent JSON
   ├── GET /ai-feedback/{scan_id}     → existing confirm/dismiss decisions
   │
   └── POST /ai-feedback              → { scan_id, finding_id, action: "confirm"|"dismiss" }
         │
         ▼
         DynamoDB: ai_feedback table
         { feedback_id, scan_id, finding_id, action, owner, created_at }
         (last action per finding_id wins; stored in Lambda memory for the session)
```

The owner field is stamped from the Cognito JWT claims at the API Gateway layer, not taken from the request body.

### Cost controls

- `AI_ANALYSIS_ENABLED` environment variable defaults to `false`. The Lambda exits early if this is not set to `true`.
- Triage is limited to the top 20 findings by severity in production (configurable for evaluation).
- The agent only investigates findings with severity HIGH.
- Only scans with at least one HIGH or MEDIUM finding trigger triage.

---

## Observability

Each Lambda and the ECS Fargate worker emit metrics using CloudWatch Embedded Metric Format (EMF). Metrics are written to `stdout` as structured JSON logs; the CloudWatch agent picks them up automatically with no additional infrastructure.

### Metrics emitted

| Metric | Dimensions | Unit | Emitted by |
|--------|-----------|------|-----------|
| `scans_total` | `scan_type`, `status` | Count | Scanner Lambda, Pentest Worker |
| `scan_duration_ms` | `scan_type` | Milliseconds | Scanner Lambda, Pentest Worker |
| `findings_total` | `language`, `severity` | Count | Scanner Lambda (one record per language × severity combination) |
| `ai_triage_total` | `status` | Count | AI Analysis Lambda |
| `agent_investigations_total` | `verdict` | Count | AI Analysis Lambda |
| `agent_duration_ms` | (none) | Milliseconds | AI Analysis Lambda |
| `human_feedback_total` | `action` | Count | Query API Lambda |

All metrics are emitted under the `ShieldScan` CloudWatch namespace.

### CloudWatch alarms

| Alarm | Condition | Notifies |
|-------|-----------|---------|
| SAST DLQ messages | `ApproximateNumberOfMessagesVisible > 0` (1 min) | SNS alert topic |
| Pentest DLQ messages | `ApproximateNumberOfMessagesVisible > 0` (1 min) | SNS alert topic |
| SAST Scanner errors | Lambda Errors > 3 (5 min) | SNS alert topic |
| Pentest Trigger errors | Lambda Errors > 3 (5 min) | SNS alert topic |
| HIGH findings spike | `findings_total{severity=HIGH}` Sum > 10 (1 hour) | SNS alert topic |

### Grafana dashboard

`platform/grafana/shieldscan-dashboard.json` is an importable Grafana dashboard that uses CloudWatch as its datasource. It includes 11 panels:

- Stat panels: total scans (7d), HIGH findings (7d), AI acceptance rate (7d), agent investigations (7d)
- Time series: scans by type over time, findings by severity, findings by language, AI triage and agent activity, human feedback (confirm vs dismiss), scan duration p95, agent duration p95

The acceptance rate panel computes `confirmed / (confirmed + dismissed)` with a safe divide to avoid division by zero.

---

## API Routes

All protected routes require a Cognito JWT in the `Authorization: Bearer` header. The token is verified by the API Gateway JWT authorizer before the request reaches any Lambda.

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| `POST` | `/webhook/sast` | HMAC-SHA256 | GitHub webhook ingestion. Validates signature, queues scan job |
| `POST` | `/scan/pentest` | JWT | Trigger a manual pentest scan |
| `GET` | `/scans` | JWT | List scans. Query params: `app_id`, `scan_type`, `repo_name`, `severity`, `limit` (1-200) |
| `GET` | `/reports/{id}` | JWT | Pre-signed S3 URL (15-min expiry) for full scan report |
| `GET` | `/apps` | JWT | List registered applications for the authenticated user |
| `POST` | `/apps` | JWT | Register an app (binds `repo_name` to `target_url`) |
| `GET` | `/triage/{id}` | JWT | Pre-signed S3 URL for AI triage report |
| `GET` | `/agent/{id}` | JWT | Pre-signed S3 URL for agent investigation report |
| `GET` | `/ai-feedback/{id}` | JWT | All confirm/dismiss decisions for a scan, keyed by `finding_id` |
| `POST` | `/ai-feedback` | JWT | Submit a confirm or dismiss decision for a finding |

---

## Dashboard

The React dashboard is built with Vite and deployed to S3 + CloudFront. All API calls include the Cognito access token from `localStorage`.

### Sections

**Scans table**

Displays paginated scan history with filters for app, scan type, repository, severity, and result count. Each row shows the scan ID, type, status, severity, and two AI badge columns: a triage summary (`TP:N FP:N NR:N`) and an agent badge (`N investigated`). Buttons in the Actions column open the full triage panel or agent panel as overlays.

**AI triage panel**

Opens as an overlay when the Triage button is clicked. Shows the AI summary counts and a table of individual findings. Each finding row displays the label badge (color-coded: red for TRUE_POSITIVE, green for FALSE_POSITIVE, yellow for NEEDS_REVIEW), confidence percentage, AI reasoning, and remediation text. Two buttons allow the reviewer to Confirm or Dismiss the AI label. The panel pre-populates any existing decisions by fetching `GET /ai-feedback/{scan_id}` on open.

**Agent investigation panel**

Opens as an overlay when the Agent button is clicked. Shows one card per investigated finding with the verdict badge (CONFIRMED in red, LIKELY_FALSE_POSITIVE in green, INCONCLUSIVE in yellow), confidence, tool call count, attack path narrative, and remediation recommendation. An expandable Investigation Trace section shows the full sequence of tool calls the agent made, including input parameters and truncated output.

**App registration and manual pentest**

A two-column form where users can register an application by binding a GitHub repository to a target URL, then immediately trigger a pentest against that target. Auth configuration (bearer token or login flow), OpenAPI spec URL, and manual endpoint lists can all be specified at registration time.

---

## AI Triage Evaluation

To verify that the triage pipeline produces accurate labels, an offline evaluation was built against a 25-finding annotated dataset.

### Dataset

**`eval/target/vulnerable.js`** contains 15 genuine vulnerabilities covering SQL injection, NoSQL injection, XSS, path traversal, `eval()`, JWT misuse, MD5 password hashing, insecure PRNG, prototype pollution, CORS wildcard, a hardcoded API key, and sensitive data logging.

**`eval/target/false_positives.js`** contains 10 cases where the scanner fires correctly by its regex rules but the finding is not exploitable: SHA-1 used for a content cache key (not for auth), `innerHTML` after an explicit `escapeHtml()` call, `Math.random()` for a transient UI element ID (not a secret), a hardcoded `127.0.0.1` localhost address, and a hardcoded placeholder password with an explicit instruction to change it.

Three of the false positive cases arise because the SAST regex fires on comment lines that happen to contain the pattern (e.g. a comment reading `// eval() with external input` on the line above the actual `eval(expression)` call). These are valid false positives that test whether the model can identify comment lines from the evidence field.

### Evaluation script

`eval/run_eval.mjs` replicates the exact production input path:

1. Calls `scanCode()` from the scanner module
2. Calls `extractContext()` to attach `±5-line code context` to each finding (same as production)
3. Calls `triageFindings()` with `maxFindings` set to the full finding count (bypasses the production cost cap of 20)
4. Compares AI labels against `eval/ground_truth.json`
5. Writes per-finding outcomes and aggregate metrics to `eval/results.json`

`NEEDS_REVIEW` is treated as a predicted positive under a conservative policy: AI uncertainty escalates to human review rather than dismissing a finding.

### Results

Model: `claude-haiku-4-5-20251001`

| Metric | Value |
|--------|-------|
| Precision | 87.5% |
| Recall | 93.3% |
| F1 score | 90.3% |
| Accuracy | 88.0% |

Confusion matrix (25 findings, 15 ground truth positives):

```
                  AI predicted positive   AI predicted negative
Ground truth TP           14 (TP)                1 (FN)
Ground truth FP            2 (FP)                8 (TN)
```

**One false negative:** The `SENSITIVE_DATA_LOG` finding at line 118 of `vulnerable.js` was labelled FALSE_POSITIVE with 0.62 confidence. The model reasoned that the function was named `debugUser`, suggesting development-only logging. The finding is a genuine production risk: `user.password` appearing in CloudWatch or any log aggregator is a real credential exposure.

**Two NEEDS_REVIEW escalations (counted as FP in metrics):** `innerHTML` after `escapeHtml()` — the model could not verify the sanitization function's implementation from context alone. A hardcoded default password — the model noted correctly that if no environment variable overrides it, the placeholder value becomes a real credential. Both cases represent genuine ambiguity where human review is the right outcome.

To re-run:

```bash
ANTHROPIC_API_KEY=sk-ant-... node eval/run_eval.mjs
```

---

## Infrastructure

All resources are provisioned via Terraform in `platform/infra/`. The module structure maps one-to-one to AWS service boundaries.

### Resource overview

| Module | Resources |
|--------|---------|
| `vpc` | VPC, public and private subnets across 2 AZs, internet gateway, NAT gateway, route tables |
| `iam` | One IAM role per Lambda function and one for the ECS task, each with least-privilege policies |
| `dynamodb` | `scans` table (PK: `scan_id`, GSIs on `repo_name`, `app_id`, `scan_type`, `severity`), `apps` table (PK: `app_id`, GSI on `owner`), `ai_feedback` table (PK: `feedback_id`) |
| `s3_reports` | S3 bucket for all scan reports, SARIF files, and AI analysis output |
| `s3_frontend` | S3 bucket for the React SPA |
| `cloudfront` | CloudFront distribution in front of the frontend bucket |
| `cognito` | User Pool with email/password auth, App Client for the dashboard |
| `api_gateway` | HTTP API with Cognito JWT authorizer, 10 routes, Lambda integrations |
| `sqs` | SAST queue + DLQ, pentest queue + DLQ (30-second visibility timeout, 3 receive retries before DLQ) |
| `sns` | Alert topic (HIGH findings + Lambda errors), SAST-complete topic (triggers AI analysis) |
| `lambda_sast` | Validator function (webhook ingestion) + Scanner function (analysis) |
| `lambda_pentest` | Trigger function (queues pentest jobs) |
| `lambda_ai_analysis` | AI analysis function (triage + agent, 300-second timeout) |
| `lambda_query` | Query API function |
| `lambda_alert` | Alert function (forwards SNS events to email) |
| `ecs_fargate` | Task definition, ECS service on private subnets, ECR repository for pentest worker image |
| `cloudwatch` | Log groups for each Lambda, CloudWatch alarms (5 alarms), CloudWatch dashboard |

### DynamoDB indexes

**`scans` table**

| Index | Partition key | Sort key | Used for |
|-------|--------------|---------|---------|
| (primary) | `scan_id` | | Point lookup by scan ID |
| `repo-time-index` | `repo_name` | `created_at` | Filter by repository |
| `app-time-index` | `app_id` | `created_at` | Filter by app (SAST × DAST correlation) |
| `type-time-index` | `scan_type` | `created_at` | Filter by SAST vs pentest |
| `severity-time-index` | `severity` | `created_at` | Filter by severity |

**`apps` table**

| Index | Partition key | Used for |
|-------|--------------|---------|
| (primary) | `app_id` | | Point lookup |
| `owner-index` | `owner` | Filter apps by Cognito user |
| `repo-index` | `repo_name` | Resolve app_id from a repo name during SAST scan |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `us-east-1` | AWS region for all resources |
| `project_name` | `shieldscan` | Prefix for all resource names |
| `environment` | `dev` | Suffix for all resource names |
| `github_token` | (required) | GitHub PAT for fetching code and posting PR comments |
| `anthropic_api_key` | (sensitive) | Anthropic API key for AI triage and agent |
| `ai_analysis_enabled` | `false` | Set to `true` to enable the AI analysis pipeline |
| `alert_email` | (required) | Email address for SNS HIGH-severity alerts |

---

## Repository Layout

```
.
├── platform/
│   ├── infra/
│   │   ├── main.tf                        # Composes all 17 modules
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── modules/
│   │       ├── vpc/
│   │       ├── iam/
│   │       ├── dynamodb/
│   │       ├── s3_reports/
│   │       ├── s3_frontend/
│   │       ├── cloudfront/
│   │       ├── cognito/
│   │       ├── api_gateway/
│   │       ├── sqs/
│   │       ├── sns/
│   │       ├── lambda_sast/
│   │       │   └── src/
│   │       │       ├── validator/index.mjs
│   │       │       └── scanner/
│   │       │           ├── index.mjs      # GitHub fetch, context extraction, SARIF write, SNS publish
│   │       │           ├── scanner.mjs    # Language routing, deduplication, finding_id assignment
│   │       │           ├── sarif.mjs      # SARIF 2.1.0 serializer
│   │       │           ├── emf.mjs
│   │       │           └── rules/
│   │       │               ├── common.mjs
│   │       │               ├── javascript.mjs
│   │       │               ├── python.mjs
│   │       │               ├── java.mjs
│   │       │               └── go.mjs
│   │       ├── lambda_pentest/
│   │       ├── lambda_ai_analysis/
│   │       │   └── src/analysis/
│   │       │       ├── index.mjs          # SNS handler, pipeline orchestration
│   │       │       ├── triage.mjs         # Batch triage via claude-haiku
│   │       │       ├── agent.mjs          # ReAct agent via claude-sonnet
│   │       │       ├── tools.mjs          # GitHub API tool implementations
│   │       │       ├── correlate.mjs      # DAST context lookup for cross-scan correlation
│   │       │       ├── schema.mjs         # Output validation for triage JSON
│   │       │       └── emf.mjs
│   │       ├── lambda_query/
│   │       │   └── src/query/index.mjs    # All 10 API routes
│   │       ├── lambda_alert/
│   │       ├── ecs_fargate/
│   │       └── cloudwatch/
│   │
│   ├── frontend/
│   │   └── src/
│   │       ├── App.jsx                    # Dashboard: scans table, triage panel, agent panel, app registration
│   │       └── styles.css
│   │
│   ├── pentest-worker/
│   │   ├── worker.mjs                     # SQS poll loop, job dispatch, S3/DynamoDB write
│   │   ├── tester.js                      # 8 DAST test implementations
│   │   ├── emf.mjs
│   │   └── Dockerfile
│   │
│   └── grafana/
│       └── shieldscan-dashboard.json      # Importable Grafana dashboard (CloudWatch datasource)
│
├── demo-vuln-target/                      # Intentionally vulnerable app for end-to-end testing
│
├── eval/
│   ├── target/
│   │   ├── vulnerable.js                  # 15 true positive findings (annotated)
│   │   └── false_positives.js             # 10 false positive findings (annotated)
│   ├── ground_truth.json                  # Human labels for all 25 findings
│   ├── run_eval.mjs                       # Evaluation script (scanner + triage + metrics)
│   └── results.json                       # Pre-run results: precision 87.5%, recall 93.3%, F1 90.3%
│
└── .github/
    └── workflows/
        └── sarif-upload.yml               # Manual workflow: download SARIF from S3, upload to GitHub Code Scanning
```
