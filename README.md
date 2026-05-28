# AI Security Compliance Agent — Project Plan

## Overview

An autonomous security compliance agent that continuously scans AWS infrastructure, evaluates findings against compliance frameworks using Claude (AWS Bedrock) with tool use, and takes action — auto-remediating low-risk issues, escalating high-risk findings to GitHub Issues, and reporting posture trends through a React dashboard.

Runs on AWS Lambda (free tier) for production. Includes full Kubernetes manifests and local Kind cluster deployment for demonstrating container orchestration skills without ongoing cloud costs.

**Repository:** `github.com/MiguelAngelHorta/AI-Compliance-Agent`

---

## Problem Statement

Security and compliance teams spend hundreds of hours per audit cycle manually reviewing infrastructure configurations, mapping findings to control frameworks, and generating remediation tickets. Most existing tools flag issues but don't reason about them — they produce noise without context, requiring human analysts to triage every finding.

This project builds an agent that closes the loop: discover, reason, decide, act, and report — with Claude providing the reasoning layer that transforms raw scan data into contextual compliance decisions.

---

## Architecture

### Production (Lambda — free tier)

```
EventBridge (every 6 hours)
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│  Lambda Function (Python 3.12)                           │
│                                                          │
│  Scanner ──▶ Reasoning Engine ──▶ Action Executor        │
│  (boto3)     (Claude + Tools)     (Remediate/Escalate)   │
└──────┬───────────────┬────────────────────┬──────────────┘
       │               │                    │
       ▼               ▼                    ▼
  ┌──────────┐  ┌────────────┐   ┌───────────────────┐
  │ AWS APIs │  │ Bedrock    │   │ DynamoDB           │
  │ IAM, S3  │  │ Claude     │   │ Findings + history │
  │ EC2, RDS │  │ Haiku      │   └─────────┬─────────┘
  └──────────┘  └────────────┘        ┌────┴────┐
                                      ▼         ▼
                                ┌─────────┐ ┌──────────┐
                                │ GitHub  │ │ React    │
                                │ Issues  │ │ Dashboard│
                                └─────────┘ └──────────┘
```

### Local Kubernetes (Kind — zero cost)

```
┌─────────────────────────────────────────────────────────────┐
│  Kind Cluster (local)                                       │
│                                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Namespace: compliance-agent                            │ │
│  │                                                        │ │
│  │  ┌──────────────┐  ┌──────────┐  ┌─────────────────┐  │ │
│  │  │ CronJob      │  │ ConfigMap│  │ ServiceAccount  │  │ │
│  │  │ Agent pod    │  │ Config   │  │ IRSA-ready      │  │ │
│  │  │ (every 6h)   │  │ values   │  │ annotations     │  │ │
│  │  └──────────────┘  └──────────┘  └─────────────────┘  │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Namespace: monitoring                                  │ │
│  │  ┌────────────┐  ┌────────┐  ┌──────────────────────┐ │ │
│  │  │ Prometheus │  │ Grafana│  │ Trivy Operator       │ │ │
│  │  └────────────┘  └────────┘  └──────────────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Component              | Technology                                              |
|------------------------|---------------------------------------------------------|
| Agent runtime          | Python 3.12, boto3, pydantic                            |
| AI reasoning           | Claude Haiku via AWS Bedrock (tool use)                  |
| Production deploy      | AWS Lambda + EventBridge (free tier)                     |
| K8s demo               | Kind (local), Helm chart, CronJob, IRSA-ready manifests |
| Container              | Docker, ECR (free tier)                                  |
| Security scanning      | Trivy (CI pipeline + Trivy Operator in Kind)             |
| Infrastructure as Code | Terraform (Lambda + DynamoDB + optional EKS module)      |
| CI/CD                  | GitHub Actions (lint, test, build, scan, deploy)         |
| Data store             | DynamoDB on-demand (free tier)                           |
| Escalation             | GitHub Issues API, Slack webhook                                  |
| Dashboard              | React + Recharts, deployed to S3 + CloudFront            |
| Testing                | pytest, moto (AWS mocking), integration tests            |
| Monitoring (local)     | Prometheus + Grafana on Kind cluster                     |

---

## Cost Estimate (Monthly)

| Service                     | Cost                                    |
|-----------------------------|-----------------------------------------|
| Lambda (4 invocations/day)  | $0 (free tier: 1M requests/month)       |
| EventBridge                 | $0 (free tier)                          |
| DynamoDB on-demand          | $0 (free tier: 25 GB, 25 RCU/WCU)      |
| Bedrock (Claude Haiku)      | $1-3 (use Haiku for scans, Sonnet for complex only) |
| ECR                         | $0 (free tier: 500 MB)                  |
| S3 + CloudFront (dashboard) | $0-1                                    |
| Kind cluster                | $0 (runs on your laptop)                |
| **Total**                   | **$1-4/month**                          |

---

## Data Model (DynamoDB)

### Findings Table

| Attribute         | Type   | Description                                    |
|-------------------|--------|------------------------------------------------|
| finding_id (PK)   | String | UUID                                           |
| scan_timestamp     | String | ISO 8601 scan time                             |
| resource_type      | String | iam_policy, s3_bucket, security_group, etc.    |
| resource_arn       | String | Full ARN of the resource                       |
| finding_type       | String | overpermissive, unencrypted, public_access, etc.|
| risk_score         | String | critical, high, medium, low                    |
| control_mappings   | List   | CIS 1.16, NIST AC-6, SOC2 CC6.1, etc.         |
| claude_reasoning   | String | Full reasoning chain from Claude                |
| remediation        | String | Recommended fix                                |
| action_taken       | String | auto_remediated, issue_created, slack_sent, none|
| action_details     | Map    | GitHub issue URL, remediation command, etc.      |
| status             | String | open, remediated, escalated, acknowledged      |

### Posture History Table

| Attribute          | Type   | Description                                    |
|--------------------|--------|------------------------------------------------|
| date (PK)          | String | YYYY-MM-DD                                     |
| total_findings     | Number | Count of all findings                          |
| critical_count     | Number | Findings by severity                           |
| high_count         | Number |                                                |
| medium_count       | Number |                                                |
| low_count          | Number |                                                |
| auto_remediated    | Number | Actions taken automatically                    |
| escalated          | Number | Tickets created                                |
| compliance_score   | Number | 0-100 weighted score                           |

---

## Claude Tool Definitions

The agent gives Claude these tools via Bedrock's tool use API. Claude decides which to call based on the findings.

### Discovery Tools (read-only)
- `list_iam_policies` — All IAM policies with permission statements
- `get_iam_policy_details` — Deep dive on a specific policy (attached entities, last used)
- `list_s3_buckets` — Bucket configs (encryption, public access, versioning)
- `list_security_groups` — Inbound/outbound rules for all security groups
- `list_rds_instances` — RDS configs (encryption, public access, backup retention)
- `list_lambda_functions` — Lambda configs (runtime, timeout, IAM role)

### Analysis Tools
- `map_to_controls` — Maps a finding to CIS/NIST/SOC2 controls
- `check_blast_radius` — Returns what depends on a given resource
- `get_historical_findings` — Past findings for the same resource

### Action Tools
- `remediate_s3_encryption` — Enables default encryption on an S3 bucket
- `remediate_s3_public_access` — Enables S3 Block Public Access
- `restrict_security_group` — Removes overly permissive inbound rules
- `create_github_issue` — Creates ticket with finding details and remediation steps
- `send_slack_alert` — Posts finding summary to Slack
- `log_decision` — Records reasoning chain and action to DynamoDB

---

## Agentic Decision Logic

```
For each finding:
  1. Claude receives the raw finding + resource context
  2. Claude calls map_to_controls to identify violated frameworks
  3. Claude calls check_blast_radius to understand impact
  4. Claude calls get_historical_findings to check if recurring
  5. Claude assigns risk_score based on all context
  6. Decision:
     - LOW risk + clear fix → call remediation tool (auto-fix)
     - MEDIUM risk → send_slack_alert with context for human review
     - HIGH/CRITICAL risk → create_github_issue with full reasoning
  7. Claude calls log_decision with full reasoning chain
```

Claude is not following a hardcoded if/else tree. It receives the tools and the finding, and reasons about which tools to call and in what order. The prompt gives it the decision framework as guidance, but Claude can deviate if context warrants it.

---

## Project Phases

### Phase 1: Foundation (Week 1-2)
**Goal:** Working scanner with CI and tests. No cloud deployment yet.

**Tasks:**
- [ ] Create GitHub repo with README, LICENSE, .gitignore
- [ ] Set up Python project: pyproject.toml, ruff, mypy, pytest
- [ ] Create project structure:
  ```
  ai-compliance-agent/
  ├── src/
  │   ├── scanner/
  │   │   ├── __init__.py
  │   │   ├── iam.py
  │   │   ├── s3.py
  │   │   ├── ec2.py
  │   │   ├── rds.py
  │   │   └── lambda_scanner.py
  │   ├── models/
  │   │   ├── __init__.py
  │   │   └── finding.py
  │   └── main.py
  ├── tests/
  │   ├── test_scanner_iam.py
  │   ├── test_scanner_s3.py
  │   └── conftest.py
  ├── Dockerfile
  ├── pyproject.toml
  └── README.md
  ```
- [ ] Implement scanner modules using boto3:
  - IAM: wildcard actions, no MFA, unused keys (90+ days), overpermissive roles
  - S3: unencrypted, public access, no versioning, no logging
  - EC2: security groups with 0.0.0.0/0 on ports 22, 3389, 3306
  - RDS: unencrypted, public access, no automated backups
  - Lambda: deprecated runtimes, overpermissive roles
- [ ] Create Finding pydantic model
- [ ] Write unit tests using moto (AWS mock library)
- [ ] GitHub Actions CI: ruff → mypy → pytest on every push

**Deliverable:** `python -m src.main --scan` prints findings JSON from a real AWS account.

---

### Phase 2: Claude Reasoning Engine (Week 3-4)
**Goal:** Claude evaluates findings, maps to controls, scores risk, recommends remediation.

**Tasks:**
- [ ] Create src/reasoner/ module
- [ ] Define Claude tool schemas (JSON) for discovery and analysis tools
- [ ] Implement Bedrock client wrapper with retry logic and cost tracking
- [ ] Build reasoning prompt with CIS v8 and NIST 800-53 control references
- [ ] Implement tool use loop:
  - Send finding to Claude with tools
  - Execute tool calls, return results
  - Claude returns assessment with risk_score, control_mappings, remediation
- [ ] Use Claude Haiku for routine findings, escalate to Sonnet for complex ones
- [ ] Create DynamoDB client for storing assessed findings
- [ ] Write integration tests with recorded Bedrock responses
- [ ] Add token/cost tracking per scan cycle

**Deliverable:** `python -m src.main --scan --reason` scans, reasons with Claude, stores results in DynamoDB.

---

### Phase 3: Agentic Actions (Week 5-6)
**Goal:** Claude decides and executes actions autonomously.

**Tasks:**
- [ ] Create src/actions/ module
- [ ] Implement remediation functions:
  - remediate_s3_encryption (enable AES-256)
  - remediate_s3_public_access (enable Block Public Access)
  - restrict_security_group (remove 0.0.0.0/0 on non-web ports)
- [ ] Implement escalation functions:
  - create_github_issue via GitHub Issues API
  - send_slack_alert via Slack webhook
- [ ] Add action tools to Claude's tool set
- [ ] Create audit log in DynamoDB for every action
- [ ] Add --dry-run flag (logs planned actions without executing)
- [ ] Write tests for each action function

**Deliverable:** `python -m src.main --scan --reason --act` runs the full agent loop. `--dry-run` previews actions.

---

### Phase 4: Deploy to Lambda + Kubernetes Demo (Week 7-8)
**Goal:** Production agent on Lambda (free). Local Kubernetes demo proving K8s skills.

#### Lambda (production, free tier)
- [ ] Package agent as Lambda function (zip or container image)
- [ ] Terraform modules:
  - `infra/lambda/` — Lambda function, EventBridge rule (every 6 hours), IAM role
  - `infra/dynamodb/` — Findings and posture history tables
  - `infra/ecr/` — Container registry
- [ ] Terraform remote state backend (S3 + DynamoDB state locking)
- [ ] GitHub Actions: build → Trivy scan → push to ECR → deploy Lambda

#### Kubernetes (local demo, zero cost)
- [ ] Write Dockerfile (multi-stage build)
- [ ] Create Helm chart:
  ```
  helm/compliance-agent/
  ├── Chart.yaml
  ├── values.yaml
  ├── values-production.yaml      # EKS-ready values with IRSA
  ├── templates/
  │   ├── cronjob.yaml            # Agent runs every 6 hours
  │   ├── configmap.yaml          # Scan targets, thresholds, dry-run toggle
  │   ├── serviceaccount.yaml     # IRSA annotations for EKS
  │   ├── networkpolicy.yaml      # Restrict pod egress
  │   └── hpa.yaml                # Horizontal pod autoscaler (for EKS)
  ```
- [ ] Create Kind cluster setup script:
  ```
  scripts/
  ├── kind-setup.sh               # Create cluster, install Trivy Operator
  ├── kind-deploy.sh              # Build image, load to Kind, helm install
  └── kind-teardown.sh            # Clean up
  ```
- [ ] Install Trivy Operator on Kind for runtime vulnerability scanning
- [ ] Install Prometheus + Grafana on Kind for monitoring demo
- [ ] Create Grafana dashboard JSON showing agent metrics (scan count, findings, actions)
- [ ] Add Terraform EKS module (optional, documented but not deployed by default):
  ```
  infra/eks/                      # Optional production K8s deployment
  ├── main.tf                     # EKS cluster, node group, OIDC
  ├── irsa.tf                     # IAM Roles for Service Accounts
  └── variables.tf
  ```
- [ ] Document both deployment paths in README:
  - Quick start: `terraform apply` (Lambda, free)
  - Kubernetes demo: `./scripts/kind-setup.sh && ./scripts/kind-deploy.sh`
  - Production K8s: `cd infra/eks && terraform apply` (costs ~$100/month)
- [ ] Record terminal demo (asciinema or GIF) showing:
  - Kind cluster creation
  - Helm install
  - CronJob running
  - kubectl logs showing scan results
  - Trivy scan results
  - Grafana dashboard

**Deliverable:** Agent runs on Lambda (free) in production. Local Kind cluster demonstrates K8s deployment, Helm charts, Trivy scanning, and Prometheus/Grafana monitoring.

---

### Phase 5: Dashboard (Week 9-10)
**Goal:** React frontend showing compliance posture and agent activity.

**Tasks:**
- [ ] Create React app with Vite + TypeScript + Tailwind
- [ ] Pages:
  - Overview: compliance score gauge, 90-day trend line, findings by severity, actions breakdown
  - Findings: sortable/filterable table, click to expand Claude's reasoning
  - Actions: timeline of agent activity (remediated, escalated, pending)
  - Controls: heatmap of CIS/NIST/SOC2 control coverage
- [ ] API layer: Lambda function reading from DynamoDB, returns JSON
- [ ] Deploy to S3 + CloudFront (same pattern as cloud resume)
- [ ] Terraform for dashboard infra
- [ ] GitHub Actions: build React → deploy to S3 → invalidate CloudFront

**Deliverable:** Live dashboard showing real scan data.

---

### Phase 6: Polish and Launch (Week 11-12)
**Goal:** Production-ready, documented, presentable.

**Tasks:**
- [ ] CloudWatch alarms on Lambda failures and DynamoDB throttling
- [ ] Bedrock cost circuit breaker (stop if > $X/day)
- [ ] README with:
  - Architecture diagrams (Lambda + K8s)
  - Quick start guide
  - Demo GIF/video of both Lambda and Kind deployments
  - Cost comparison table (Lambda vs EKS)
- [ ] Security hardening:
  - Least-privilege IAM (separate scanner read role from action write role)
  - Secrets in AWS Secrets Manager
  - Network policies in K8s manifests
- [ ] Write LinkedIn post explaining the project
- [ ] Record 2-minute demo video

**Deliverable:** Public repo, live dashboard, LinkedIn post, demo video.

---

## What This Proves on Your Resume

| Skill                        | Evidence                                              |
|------------------------------|-------------------------------------------------------|
| Python backend engineering   | Scanner, reasoner, action modules with tests          |
| AI / agentic architecture    | Claude tool use, autonomous decision loop             |
| Kubernetes                   | Helm chart, CronJob, IRSA, NetworkPolicy, Trivy Operator, Prometheus, Grafana — all running on local Kind |
| Docker                       | Multi-stage Dockerfile, ECR, image scanning           |
| Terraform                    | Lambda, DynamoDB, ECR, S3/CloudFront, optional EKS    |
| CI/CD                        | GitHub Actions: lint, test, build, Trivy scan, deploy |
| Testing                      | pytest, moto, integration tests, 80%+ coverage        |
| Security tooling             | Trivy (CI + runtime), least-privilege IAM, NetworkPolicy |
| Data modeling                | DynamoDB schema design, posture trending              |
| React frontend               | Dashboard with charts, tables, drill-downs            |
| GRC domain expertise         | CIS, NIST, SOC2 control mapping built into the agent  |
| Observability                | Prometheus metrics, Grafana dashboards, CloudWatch    |

---

## Kubernetes Skills Demonstrated (Zero Cost)

The Kind cluster proves all the K8s concepts a hiring manager would look for:

- **CronJob scheduling** — agent runs on a cron schedule, same as EKS
- **Helm charts** — parameterized deployment with values files for dev/prod
- **ServiceAccount + IRSA annotations** — ready to swap in real AWS IAM roles on EKS
- **ConfigMap** — externalized config (scan targets, thresholds, dry-run mode)
- **NetworkPolicy** — pod egress restricted to AWS APIs and Slack/GitHub
- **Trivy Operator** — runtime vulnerability scanning of running containers
- **Prometheus + Grafana** — metrics collection and dashboarding
- **HPA template** — horizontal pod autoscaler ready for EKS (dormant on Kind)
- **Multi-environment Helm values** — values.yaml (local) vs values-production.yaml (EKS)

The README documents the EKS upgrade path: swap Kind for EKS, enable IRSA, apply values-production.yaml. The manifests are production-ready — the only difference is where the cluster runs.

---

## Success Metrics

| Metric                         | Target                        |
|--------------------------------|-------------------------------|
| Scan coverage                  | IAM, S3, EC2, RDS, Lambda    |
| Control frameworks mapped      | CIS v8, NIST 800-53, SOC 2   |
| Auto-remediation rate          | 30%+ of low-risk findings     |
| Scan-to-action time            | < 5 minutes per finding       |
| CI pipeline                    | Lint, test, build, scan, deploy |
| Test coverage                  | > 80%                         |
| Monthly cost                   | < $5                          |
| K8s concepts demonstrated      | 9 (CronJob, Helm, IRSA, ConfigMap, NetworkPolicy, Trivy, Prometheus, Grafana, HPA) |

---

## Risk Mitigation

| Risk                              | Mitigation                                    |
|-----------------------------------|-----------------------------------------------|
| Auto-remediation breaks something | Dry-run mode default; auto-fix only for reversible actions |
| Bedrock costs spike               | Use Haiku by default; Sonnet only for complex findings; token budget per cycle |
| Kind cluster issues on different OS| Document setup for macOS, Linux, Windows; provide Docker Desktop fallback |
| Claude hallucinates control mappings | Include control definitions in prompt; validate against lookup table |
| Scope creep                       | Each phase ships independently; dashboard (Phase 5) is cuttable |

---

## Timeline Summary

| Week  | Phase                        | Key Deliverable                          |
|-------|------------------------------|------------------------------------------|
| 1-2   | Foundation                   | Working scanner with CI and tests        |
| 3-4   | Claude reasoning engine      | Findings assessed and stored in DynamoDB |
| 5-6   | Agentic actions              | Auto-remediation and GitHub Issues escalation |
| 7-8   | Lambda + K8s demo            | Free Lambda deploy + local Kind cluster  |
| 9-10  | Dashboard                    | React compliance dashboard live          |
| 11-12 | Polish + launch              | README, demo video, LinkedIn post        |
