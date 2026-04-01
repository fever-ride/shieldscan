# ShieldScan — Product Document & Roadmap

> **设计原则**：面向个人展示（面试/portfolio）的项目。所有功能设计以"端到端可演示、技术决策可解释、不超卖"为标准，而非生产 SaaS 级别。

---

## 一、产品定位

ShieldScan 是一个**轻量云原生应用安全平台**，将静态代码分析（SAST）、动态渗透测试（DAST）与 AI 安全顾问层三者统一在同一工作流中，面向小型安全团队或独立开发者。

**核心价值主张：**
> 把静态发现、动态验证、AI 建议和人工复核串起来——让安全发现从"一堆告警"变成"可操作的优先级列表"。

**不是什么：**
- 不是企业级多租户 SaaS（无 RBAC，owner 级隔离）
- AI 不自动改变漏洞状态，只提供建议，由人工确认
- 不是全量代码分析（每次扫描最多 100 个文件，适合中小型 repo）
- 不是自主漏洞利用工具（不同于 FAAST 的全自主 agent 路线）

---

## 二、与现有工具的对比

> 注：ShieldScan 不是这些工具的替代品，而是展示"如何把 SAST/DAST/AI advisory workflow 串起来"的 portfolio 项目。

| 工具 | 类型 | 主要用途 | ShieldScan 补充的视角 |
|---|---|---|---|
| Semgrep | SAST | 静态规则扫描 | 加入 DAST 动态验证 + AI 辅助分析建议 |
| Snyk | SCA | 依赖漏洞扫描 | 扫代码逻辑，不只看依赖 |
| CodeQL | SAST | 深度语义分析 | 更轻量，易部署，适合 CI/CD 快速集成 |
| Burp Suite | DAST | 手动渗透测试 | 全自动触发，结果关联代码层静态发现 |
| GitHub GHAS | SAST + Secrets | GitHub 原生安全扫描 | 加入 DAST + AI advisory + 人工复核流 |
| **FAAST** | **SAST+DAST Agent** | **自主漏洞利用 POC** | **设计方向相反：ShieldScan 选择 human-in-the-loop** |

**与 FAAST 的核心区别：**

FAAST 是三段式全自主 agent（SAST agent → Endpoint trace agent → 浏览器自动利用），目标是让 AI 自主完成整个渗透测试，是研究 POC。

ShieldScan 选择相反方向：用确定性规则做扫描基础，AI 只做建议层，人工确认后才改变状态。原因是：在安全判断里误判代价很高，human-in-the-loop 是工程实践中更负责任的设计。

---

## 三、系统架构

### 3.1 当前架构（已实现）

```
GitHub Webhook
    ↓
API Gateway
    ├── POST /webhook/sast  → Lambda Validator → SQS → Lambda Scanner
    │                                                        ↓
    │                                           GitHub API 取代码
    │                                                        ↓
    │                                      多语言规则扫描 (JS/TS/Py/Java/Go)
    │                                                        ↓
    │                                      DynamoDB + S3 + PR Comment + SNS
    │
    ├── POST /scan/pentest  → Lambda Trigger → SQS → ECS Fargate Worker
    │                                                        ↓
    │                                              6 类动态安全测试
    │                                                        ↓
    │                                              DynamoDB + S3 + SNS
    │
    └── GET /scans, /reports, /targets → Lambda Query → DynamoDB + S3
                                                  ↓
                                            React Dashboard (Cognito Auth)
```

### 3.2 目标架构（改造后）

新增两层，不引入 K8s / Prometheus / BullMQ：

```
[现有 SAST / DAST 流程不变]
    ↓ SAST 完成后触发
┌──────────────────────────────────────────────────────────┐
│ lambda_ai_analysis（新增）                                │
│                                                          │
│  Step 1: Triage Pipeline（秒级，所有 findings）           │
│    → 单次 LLM call，批量输出三态标签                      │
│    → likely_real / uncertain / likely_false_positive     │
│    → 产出 high_priority_for_investigation 列表            │
│                                                          │
│  Step 2: Deep Investigation Agent（top 3 HIGH findings） │
│    → ReAct loop，Anthropic SDK tool use                  │
│    → 3 个工具（均调 GitHub API）：                        │
│        get_file_context / search_code / get_directory_tree│
│    → Agent 自主决定调哪个 tool、调几次、何时停止          │
│    → Guardrails: max 10 tool calls / 3min / 100k tokens  │
│    → 输出 verdict + attack_path + evidence_chain         │
│                                                          │
│  若同 app 有近期 DAST 结果 → 追加跨扫描 app-level 关联分析│
│  写回 DynamoDB ai_* 字段 + S3 ai/{scan_id}.json          │
│  Dashboard 展示，人工 Confirm / Dismiss                   │
└──────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────┐
│ Observability（新增）                                     │
│  Lambda → CloudWatch EMF（原生，零额外成本）              │
│  Grafana 用 CloudWatch 作为 datasource                    │
│                                                          │
│  核心 metrics：                                           │
│    scans_total {type, status}                            │
│    findings_total {severity, language}                   │
│    ai_triage_total, agent_investigations_total           │
│    human_confirmed_total, human_dismissed_total          │
│    scan_duration_ms, agent_duration_ms                   │
└──────────────────────────────────────────────────────────┘
```

---

## 四、AI 层设计：Triage Pipeline + Deep Investigation Agent

> 两层分工：**Pipeline 做快速批量分诊，Agent 对 HIGH finding 做深度代码溯源。**
> 能 pipeline 的就不用 agent；只有调查路径未知时才上 ReAct。

### 4.1 为什么两层

| | Triage Pipeline | Deep Investigation Agent |
|---|---|---|
| 任务 | 批量标注所有 findings | 深度溯源 top 3 HIGH findings |
| 输入确定性 | 高（结构化 JSON） | 低（不知道需要追多深） |
| 工具调用 | 无 | 动态（agent 自主决定） |
| 耗时 | 秒级 | 10–30 秒 / finding |
| 适合用 | Pipeline | ReAct Agent |

Agent 用在深度溯源的理由：追踪一个 SQL injection，可能要先看函数体 → 追调用链 → 查路由 → 确认有无 middleware 防护。这个调查路径事先不知道，每一步结果决定下一步，这是 agent 存在的理由，而不是为了简历好看。

### 4.2 设计原则

- AI 输出是建议层，finding 状态只有人工在 Dashboard 操作才改变
- 所有 AI 建议标注 "AI Suggestion — requires human review"
- Agent 的每一步推理（evidence_chain）完整记录，可在 Dashboard 展开，不是黑盒
- 隐私边界：只通过 GitHub API 读取代码片段，不上传完整文件内容

### 4.3 层一：Triage Pipeline

```
输入：scan 内所有 findings JSON + 各 finding evidence snippet

System prompt:
  你是应用安全分析师。对每个 finding 快速评估：
  这是真实漏洞、可能误报、还是不确定？给出标签和简短理由。
  你的输出是建议，最终判断由人工完成。

输出（schema validated）：
{
  "scan_id": "...",
  "triage_completed_at": "...",
  "summary": {
    "total": 12,
    "likely_real": 3,
    "uncertain": 5,
    "likely_false_positive": 4,
    "high_priority_for_investigation": ["finding_id_1", "finding_id_2", "finding_id_3"]
  },
  "labels": [
    {
      "finding_id": "...",
      "label": "likely_real | uncertain | likely_false_positive",
      "reason": "Unsanitized user input passed directly to query builder"
    }
  ]
}
```

### 4.4 层二：Deep Investigation Agent（ReAct）

**工具集（3 个，全部基于现有 GitHub API）：**

| Tool | API | 用途 |
|---|---|---|
| `get_file_context(repo, path, start, end)` | GitHub Contents API | 查看 finding 周围代码 |
| `search_code(repo, query)` | GitHub Search API | 追踪函数定义、调用链、路由声明 |
| `get_directory_tree(repo, directory)` | GitHub Trees API | 了解项目结构，找 routes/middleware |

**一次典型调查过程：**

```
Finding: SQL_INJECTION in src/user.js line 47

Step 1  Think: "先看这行代码的上下文"
        Act:   get_file_context(user.js, 42, 55)
        Obs:   发现调用了 buildQuery(req.body.id)

Step 2  Think: "buildQuery 有没有做参数化处理"
        Act:   search_code("function buildQuery")
        Obs:   在 db/helpers.js:12，直接字符串拼接

Step 3  Think: "这个路由有没有 input validation middleware"
        Act:   search_code("router.post.*user")
        Obs:   找到 routes/user.js，无 validation middleware

Step 4  Think: "全局有没有 sanitize/escape 相关防护"
        Act:   search_code("sanitize|validateId|escape")
        Obs:   无匹配

Think: "攻击路径完整，无防护，可以得出结论" → 输出报告
```

**Agent 输出结构：**

```json
{
  "finding_id": "...",
  "verdict": "strong_evidence_real",

  "attack_path": [
    "POST /api/user — no input validation middleware",
    "userController.queryUser() receives req.body.id directly",
    "Passed to buildQuery() in db/helpers.js",
    "Concatenated into SQL string at line 12 — no parameterization"
  ],

  "evidence_chain": [
    { "step": 1, "tool": "get_file_context", "query": "user.js:42-55",       "finding": "calls buildQuery(req.body.id)" },
    { "step": 2, "tool": "search_code",      "query": "function buildQuery", "finding": "direct string concat in db/helpers.js:12" },
    { "step": 3, "tool": "search_code",      "query": "router.post.*user",   "finding": "no validation middleware on route" },
    { "step": 4, "tool": "search_code",      "query": "sanitize|escape",     "finding": "no sanitization found globally" }
  ],

  "existing_mitigations": "None found",
  "remediation": {
    "code": "db.query('SELECT * FROM users WHERE id = ?', [req.body.id])",
    "explanation": "使用参数化查询，将用户输入作为参数而非拼接到 SQL 字符串"
  },
  "tools_called": 4,
  "duration_ms": 8200
}
```

`evidence_chain` 在 Dashboard 展示为可展开的调查步骤，用户能看到 agent 怎么一步步得出结论。

### 4.5 Guardrails 汇总

| 约束 | 值 | 作用 |
|---|---|---|
| Triage token budget | findings ≤ 80k tokens（超出截断至 top 20） | 成本控制 |
| Agent max tool calls | 10 次 / finding | 防止无限循环 |
| Agent timeout | 3 分钟 / finding | Lambda 限制 |
| Agent max findings | top 3 HIGH | 成本控制 |
| Schema validation | zod 验证，失败重试最多 2 次 | 输出稳定性 |
| Fallback | AI 失败时展示原始 findings，主流程不受影响 | 可用性 |
| 隐私边界 | 只读代码片段，不上传完整文件 | 数据安全 |
| Feature flag | `AI_ANALYSIS_ENABLED=false` 默认关闭 | 本地开发不产生费用 |

### 4.6 AI 评估与校准

**方案（轻量可实现）：**

```
评估集来源：demo-vuln-target/ 项目（已知漏洞）
  - ~20 条 SAST findings，人工标注 ground truth（real / false_positive）
  - 覆盖各语言、各规则类型

离线评估流程：
  1. 对评估集跑 Triage Pipeline
  2. 对比 AI label 与 ground truth
  3. 计算 precision / recall（以 likely_real 为 positive）
  4. 记录到 eval/results.json，commit 进 repo

报告格式：
  {
    "eval_date": "2025-XX-XX",
    "dataset_size": 20,
    "precision": 0.78,
    "recall": 0.83,
    "uncertain_rate": 0.15,
    "notes": "Eval set from demo-vuln-target/, manually labeled"
  }
```

面试时可以说："我们用 demo app 的已知漏洞做了 20 条评估，precision ~0.78，recall ~0.83。这是 PoC 级别的评估，不是大规模 benchmark，但能证明 AI 标签有实际依据，而不是模型自说自话。"

### 4.7 Human Feedback 闭环

confirm / dismiss 操作存入 DynamoDB，不是只做展示：

```
Table: ai_feedback
  scan_id, finding_id, ai_label, human_decision (confirmed/dismissed),
  decided_by (owner), decided_at

用途：
  1. Metrics：AI 建议采纳率（Grafana 可视化，体现 AI 价值）
  2. 未来 fine-tuning 数据基础（当前 out of scope，但架构支持）
  3. 操作审计：谁、何时、对哪条 finding 做了什么决定

注：当前是单用户系统（owner = Cognito sub），confirm/dismiss 无协作冲突
```

---

## 五、SAST × DAST 关联设计

### 5.1 关联层级（明确分级，避免超卖）

| 层级 | 说明 | 状态 |
|---|---|---|
| App-level | 同一 `app_id` 下的 SAST + DAST 结果一起送入 AI 分析 | Phase 1 实现 |
| Heuristic route | 文件路径 pattern 推断可能相关端点（`routes/`、`@GetMapping` 等） | Phase 3 实现 |
| Endpoint-level | SAST finding 精确追踪到被 DAST 验证的同一 HTTP 端点 | 超出范围，需 AST 分析 |

**已知局限（面试时主动说）：**
- 一个 app 只能绑定一个 repo + 一个 target（不支持 monorepo / 微服务）
- Route inference 是启发式的，不保证准确
- 不是"攻击链 confirmed"，是"同 app 内的相关性提示"

### 5.2 关联成立的最低前提（Phase 1 必须做）

- `app` 实体同时持有 `repo_name`（SAST 关联键）和 `target_url`（DAST 关联键）
- DAST 测试结果记录被测端点路径（`/api/user`、`/login` 等）
- AI 基于同一 `app_id` 做跨扫描推理

---

## 六、各组件详细说明

### 6.1 SAST 引擎（已实现）

- 多语言规则：JS/TS、Python、Java、Go（4 语言，~60 条规则）
- 插件式 rules/ 架构：`common.mjs` + 各语言规则文件
- 输出：DynamoDB summary + S3 JSON report + GitHub PR comment + SNS alert
- **待加**：SARIF 输出（Phase 4）、代码上下文提取（Phase 2 前置）

### 6.2 DAST 引擎（已实现）

- 6 类测试：认证缺失、SQL 注入、NoSQL 注入、速率限制、安全响应头、敏感数据暴露
- ECS Fargate 长运行 worker，SQS 触发
- **待加**：测试结果记录端点路径（Phase 1 必须）、SSRF / XXE / Open Redirect（Phase 4）

### 6.3 AI 层（新增，Phase 2–3）

**Lambda 函数：`lambda_ai_analysis`，文件结构：**

```
lambda_ai_analysis/src/
  index.mjs        ← Lambda handler，协调两层
  triage.mjs       ← Triage Pipeline：单次 LLM call，批量标注
  agent.mjs        ← Deep Investigation：ReAct loop
  tools.mjs        ← 3 个 tool 实现（GitHub API）
  schema.mjs       ← 输出 schema + zod validation
  correlate.mjs    ← app-level SAST × DAST 预处理
```

### 6.4 Observability（新增，Phase 3）

- 各 Lambda 结束时 emit CloudWatch EMF metrics（原生，零额外部署）
- Grafana dashboard 用 CloudWatch 作为 datasource（不需要自建 Prometheus）
- 核心展示：漏洞趋势 / AI 建议采纳率 / 扫描吞吐量 / agent 调查耗时

### 6.5 自定义规则引擎（选做，Phase 5+）

- 用户在 Dashboard 上创建自定义规则（regex + 描述 + severity）
- 规则存 DynamoDB，Scanner Lambda 动态加载
- 支持规则测试沙箱

---

## 七、数据模型

### 新增：apps 表（关联实体，Phase 1 核心）

```
Table: apps
  PK: app_id (UUID)
  Fields:
    app_name:   string
    repo_name:  string   ← SAST 关联键 (e.g. "fever-ride/demo")
    target_url: string   ← DAST 关联键 (e.g. "https://demo.example.com")
    owner:      string   ← Cognito sub（单用户隔离）
    created_at: timestamp

GSI: owner-index  (owner → 按用户过滤)
GSI: repo-index   (repo_name → SAST 完成后找对应 app)
```

### 扩展：scans 表

```
现有字段保留，新增：
  app_id:                  string    ← 关联 apps 表
  owner:                   string    ← Cognito sub（查询过滤）
  ai_analyzed:             boolean
  ai_triage_s3_key:        string
  ai_agent_s3_key:         string
  ai_likely_real:          number
  ai_likely_false_positive:number
  ai_uncertain:            number
  ai_agent_investigated:   number    ← agent 深度调查了几条
  enriched_at:             timestamp

新增 GSI: app_id-index  (app_id + created_at)
新增 GSI: owner-index   (owner + created_at)
```

### 新增：ai_feedback 表

```
Table: ai_feedback
  PK: feedback_id (UUID)
  Fields:
    scan_id, finding_id, ai_label, human_decision, decided_by, decided_at

GSI: scan_id-index
```

### S3 报告结构

```
s3://bucket/sast/{scan_id}.json          ← 原始 SAST 报告（现有）
s3://bucket/pentest/{scan_id}.json       ← 原始 DAST 报告（现有）
s3://bucket/ai/triage/{scan_id}.json     ← Triage 结果（新增）
s3://bucket/ai/agent/{scan_id}.json      ← Agent 调查结果（新增）
s3://bucket/sarif/{scan_id}.sarif        ← SARIF 格式（Phase 4 新增）
```

### API 变更（lambda_query）

```
现有接口保留，新增：
  GET  /apps                              ← 按 owner 过滤
  POST /apps                              ← 创建 app（绑定 repo + target_url）
  GET  /scans?app_id=xxx                  ← 按 app 筛选
  GET  /ai/triage/{scan_id}              ← 读取 Triage 结果
  GET  /ai/agent/{scan_id}               ← 读取 Agent 调查结果
  POST /findings/{finding_id}/confirm    ← 人工确认
  POST /findings/{finding_id}/dismiss    ← 人工驳回
```

---

## 八、分阶段实施计划

> 每个 Phase 结束时必须有可演示的端到端流程。

---

### ✅ Phase 0 — 已完成

- [x] 多语言 SAST 引擎：JS/TS / Python / Java / Go，60+ 规则，插件式 rules/ 架构
- [x] 项目重组（platform/ 结构）+ 推送 GitHub（fever-ride/shieldscan）

---

### Phase 1 — App 实体 + 关联数据模型

**目标：** 建立 SAST × DAST 关联的数据基础。没有这层，AI 跨扫描分析是空的。

**Terraform / 基础设施：**
- [ ] 新建 DynamoDB `apps` 表（app_id / repo_name / target_url / owner / created_at）
- [ ] `apps` 表新增 GSI：owner-index / repo-index
- [ ] `scans` 表新增字段：app_id / owner（Terraform migration）
- [ ] `ai_feedback` 表新建

**后端：**
- [ ] lambda_query 新增 `GET /apps`、`POST /apps`（按 owner 过滤）
- [ ] lambda_query `GET /scans` 支持 `?app_id=` 筛选
- [ ] SAST Lambda：webhook 触发时根据 repo_name 自动查找并关联 app_id
- [ ] DAST worker：触发时写入 app_id + 记录被测端点路径

**前端：**
- [ ] Dashboard 新增"Apps"页面（创建 app，绑定 repo_name + target_url）
- [ ] Scans 列表支持按 app 筛选

**验收标准：** 触发一次 SAST + 一次 DAST，两条 scan 记录均带同一 app_id，在 Dashboard 上能筛选到。

---

### Phase 2 — AI Triage Pipeline

**目标：** 快速批量分诊所有 findings，秒级完成，建立 AI advisory 基础设施。

**基础设施：**
- [ ] 新建 `lambda_ai_analysis` Lambda（Terraform module）
- [ ] SNS topic：SAST 完成 → 触发 AI Lambda
- [ ] `AI_ANALYSIS_ENABLED` 环境变量（默认 false）

**Triage Pipeline 实现：**
- [ ] `triage.mjs`：单次 LLM call，批量输出三态标签
- [ ] 输出 schema 定义（`schema.mjs`）+ zod validation
- [ ] SAST findings 代码上下文提取（每个 finding 前后各 5 行）
- [ ] 结果写 S3 `ai/triage/{scan_id}.json` + DynamoDB `ai_*` 字段
- [ ] 失败时 fallback：记录错误，不影响主扫描流程

**Dashboard：**
- [ ] Findings 列表新增 AI 标签列（likely_real / uncertain / likely_false_positive）
- [ ] 标签旁显示 AI reasoning（tooltip 或展开）
- [ ] 明显标注 "AI Suggestion — requires human review"
- [ ] Confirm / Dismiss 按钮 → 写 ai_feedback 表

**PR comment 更新：**
- [ ] 在现有 PR comment 中追加 Triage 摘要（likely_real N 条 / uncertain N 条）

**验收标准：** SAST 完成后自动触发 Triage，Dashboard 中每条 finding 都有 AI 标签，可以 confirm/dismiss。

---

### Phase 3 — Deep Investigation Agent

**目标：** 对 top 3 HIGH findings 跑 ReAct agent，产出完整调查链。

**Agent 实现：**
- [ ] `agent.mjs`：ReAct loop，Anthropic SDK tool use
- [ ] `tools.mjs`：实现 3 个工具
  - `get_file_context` → GitHub Contents API
  - `search_code` → GitHub Search API
  - `get_directory_tree` → GitHub Trees API
- [ ] Guardrails 实现：max 10 tool calls / 3min timeout / schema retry
- [ ] 结果写 S3 `ai/agent/{scan_id}.json`

**跨扫描关联：**
- [ ] `correlate.mjs`：DAST 完成时，查同 app 7天内 SAST 结果
- [ ] 若存在 → 将 DAST endpoint 结果追加到 agent context

**Dashboard：**
- [ ] Agent 调查结果展示（verdict + attack_path）
- [ ] evidence_chain 可展开（展示 agent 推理步骤）
- [ ] 区分 Triage 标签（快速） vs Agent verdict（深度）

**验收标准：** 对 demo-vuln-target 的 HIGH finding 触发 agent，Dashboard 上能看到完整的 evidence_chain。

---

### Phase 4 — Observability

**目标：** CloudWatch EMF + Grafana，展示平台运营视角。

- [ ] 各 Lambda 结束时 emit CloudWatch EMF metrics（namespace: `ShieldScan/`）
  - `scans_total{type, status}`
  - `findings_total{severity, language}`
  - `ai_triage_total`、`agent_investigations_total`
  - `human_confirmed_total`、`human_dismissed_total`
  - `scan_duration_ms`、`agent_duration_ms`
- [ ] Grafana dashboard（CloudWatch datasource）
  - 漏洞趋势图（按时间 / 语言 / severity）
  - AI 建议采纳率（confirm vs dismiss）
  - Agent 调查耗时分布
- [ ] Grafana dashboard JSON commit 进 repo（可复现）
- [ ] CloudWatch Alarm：HIGH finding > N 条时触发 SNS

**验收标准：** Grafana 上能看到完整的扫描历史 + AI 建议采纳率趋势。

---

### Phase 5 — 行业标准：SARIF + DAST 增强

**目标：** 展示安全生态认知，对接 GitHub Security tab。

**SARIF：**
- [ ] SAST findings → SARIF 2.1.0 JSON schema
- [ ] S3 存储 `sarif/{scan_id}.sarif`
- [ ] GitHub Actions workflow：上传 SARIF → GitHub Security tab 展示

**DAST 增强：**
- [ ] 测试结果精确记录被测端点路径（为 Phase 3 关联服务）
- [ ] 新增检测类型：SSRF、Open Redirect、XXE

**验收标准：** GitHub repo Security tab 中能看到 ShieldScan 上报的漏洞。

---

### Phase 6 — AI 评估基线

**目标：** 建立评估集，让 AI 标签有实际依据，面试可以量化回答。

- [ ] 在 `demo-vuln-target/` 中人工标注 ~20 条 findings（ground truth）
- [ ] 离线跑 Triage Pipeline，记录结果
- [ ] 计算 precision / recall，存 `eval/results.json`
- [ ] README 中注明评估结论

---

### Phase 7 — 自定义规则引擎（选做）

- [ ] DynamoDB `custom_rules` 表
- [ ] Dashboard 规则编辑器（regex + 描述 + severity）
- [ ] Scanner Lambda 动态加载用户规则
- [ ] 规则测试沙箱（输入代码片段，预览匹配结果）

---

## 九、明确不做（及原因）

| 放弃的东西 | 原因 |
|---|---|
| K8s + Helm | Lambda/SQS/Fargate 已是完整云原生架构；K8s 引入第二套平台，无法 justify |
| Prometheus | Lambda 架构用 CloudWatch EMF 更原生；Grafana 可直接接 CloudWatch，不需要 Prometheus |
| 企业级 RBAC | 超出 portfolio 定位；owner-level 隔离够用 |
| 全量代码分析 | 100 文件限制下"全局上下文"不成立；文档统一说"扫描结果级上下文" |
| 自主漏洞利用 | 设计决策：human-in-the-loop 比全自主更负责任（FAAST 走的是另一条路） |
| AST taint analysis | 工程量过大；用 heuristic route inference 替代，局限在文档中明确说明 |

---

## 十、简历写法（Phase 5 完成后）

```
ShieldScan — Cloud-native Application Security Platform
github.com/fever-ride/shieldscan

• Unified SAST + DAST platform on AWS (Lambda, ECS Fargate, SQS, DynamoDB, S3, Cognito)
  triggered by GitHub webhooks; multi-language static analysis (JS/TS, Python, Java, Go)

• Designed a two-layer AI advisory system using Anthropic Claude API:
  (1) Triage Pipeline: single LLM call to batch-label all findings with three-state classification;
  (2) Deep Investigation Agent: ReAct loop with 3 GitHub API tools for autonomous code tracing
  on top HIGH findings — producing evidence chains showing each reasoning step.
  All AI output is advisory; human confirm/dismiss required to change finding status.

• Cross-correlates SAST and DAST results via a shared app entity (repo_name + target_url),
  enabling AI to reason across scan types within the same project context.

• SAST engine: 60+ rules across 4 languages in a pluggable rule registry;
  outputs SARIF for native GitHub Security tab integration.

• Observability: CloudWatch EMF metrics + Grafana dashboard tracking scan throughput,
  AI triage accuracy (via human feedback), and agent investigation latency.

• Full IaC with Terraform: VPC, API Gateway, Cognito, SQS, SNS, DynamoDB, ECS Fargate.
```

---

## 十一、面试常见问题预案

**Q: 为什么用 agent，而不是直接 pipeline？**
> Pipeline 用在批量分诊（输入确定，路径固定）。Agent 只用在 top 3 HIGH findings 的深度溯源——追踪一个 SQL injection 需要先看函数体、再追调用链、再查路由、再确认防护，这个路径事先不知道。能 pipeline 的不用 agent，只有调查路径开放时才上 ReAct。

**Q: AI 会不会误判，怎么证明标签是有意义的？**
> 我们用 demo app 的已知漏洞建了 20 条评估集，离线跑 Triage，precision ~0.78，recall ~0.83。这是 PoC 级评估，不是大规模 benchmark，但能证明标签有依据。此外标签是三态（likely_real / uncertain / likely_false_positive），不是浮点分，避免过度精确的假象。

**Q: SAST × DAST 怎么关联，endpoint 级别能做到吗？**
> Phase 1 做 app-level 关联：同一 app_id 下的 SAST + DAST 结果一起送 AI 分析。Phase 3 加 heuristic route inference（文件路径 pattern）。精确 endpoint-level 需要 AST 分析，超出当前范围，我们在文档里明确说了这个局限。

**Q: 为什么不用 K8s？**
> Lambda/SQS/Fargate 已经是完整的事件驱动云原生架构。K8s 解决的是容器编排问题，引入它需要同时维护两套平台，这对当前架构是纯粹的负担，没有 justify 的理由。

**Q: agent 的 tool 为什么只有 3 个？**
> 3 个工具覆盖了"查上下文 / 搜代码 / 看目录结构"三类调查动作，对代码溯源任务已经足够。工具集应该围绕任务设计，而不是越多越好。

**Q: 和 FAAST 有什么区别？**
> FAAST 走全自主路线——AI 直接尝试利用漏洞，是研究 POC。ShieldScan 选择相反方向：确定性规则做扫描基础，AI 做建议层，人工确认。因为在安全判断里误判代价很高，human-in-the-loop 是更负责任的设计。

**Q: 100 文件上限够用吗？**
> 适合中小型 repo。大型 repo 可以扩展策略（按目录优先级排序、跳过 test 目录等），架构上支持，是配置问题不是设计问题。

**Q: AI 做了错误建议怎么办？**
> AI 永远是建议层，finding 状态不会自动改变。用户 dismiss 一条建议就完成了"纠错"。所有 confirm/dismiss 都存 ai_feedback 表，可以做采纳率统计，未来也可以作为 fine-tuning 数据基础。
