# AI-Powered AWS Compliance Auditor

[![CI](https://github.com/MiguelAngelHorta/AI-Compliance-Agent/actions/workflows/ci.yaml/badge.svg)](https://github.com/MiguelAngelHorta/AI-Compliance-Agent/actions/workflows/ci.yaml)
![Python](https://img.shields.io/badge/python-3.12-blue)

An AI-powered AWS compliance auditor that scans IAM, S3, and EC2, then reasons about each finding with Claude (via Amazon Bedrock tool use) — mapping it to CIS v8 / NIST 800-53 / SOC 2 controls and scoring its contextual risk. A deterministic, auditable policy then routes each finding: escalating critical ones to GitHub Issues with masked identifiers, and acknowledging or logging the rest. It runs locally as a CLI and as a hardened, scheduled CronJob on Kubernetes, exposing run metrics to Prometheus/Grafana.

Most scanners flag issues but don't reason about them — they produce noise without context, leaving an analyst to triage every finding. This tool adds a reasoning layer: Claude turns raw scan data into contextual, control-mapped assessments, and a transparent policy decides what to do with them.

> Every resource name, account ID, ARN, and identifier in this README and its screenshots is a placeholder or redacted. Real values are never committed, and the auditor masks resource identifiers in all publications.

**AWS scan and Bedrock AI analysis**

<img width="1050" height="718" alt="AWS scan and Bedrock analysis" src="https://github.com/user-attachments/assets/b64526cb-146a-4914-9fe8-e3edd4d39c89" />

**Kubernetes deployment**

<img width="2596" height="1745" alt="Kubernetes deployment" src="https://github.com/user-attachments/assets/20fc9b46-46c9-4827-b932-0d94d9d552e7" />

**Pushgateway metrics**

<img width="1493" height="812" alt="Pushgateway metrics" src="https://github.com/user-attachments/assets/05d34fcf-625b-415b-99ab-05df22c6ba41" />

**Grafana reporting**

<img width="1568" height="782" alt="Grafana dashboard" src="https://github.com/user-attachments/assets/3f5ec395-7840-439f-828d-701641367c5b" />

---

## What it does

For each scan cycle the auditor:

1. **Scans** IAM, S3, and EC2 with read-only `boto3` calls and classifies findings by type and severity.
2. **Reasons** about each finding with Claude (Bedrock), which maps it to CIS v8 / NIST 800-53 / SOC 2 controls, scores its real risk in context, and proposes a remediation.
3. **Acts** via a deterministic, auditable policy: escalates critical findings to GitHub Issues with masked identifiers, and acknowledges or logs the rest. No infrastructure is modified. **Dry-run by default.**
4. **Reports** run metrics to Prometheus (via Pushgateway) for Grafana dashboarding.

The LLM does the judgment (control mapping, contextual risk scoring, remediation guidance); a transparent severity-based policy makes the routing decision. That separation is deliberate — for a tool that takes action on security findings, you want the decision logic to be deterministic and auditable, not model-driven.

---

## Highlights

- **LLM-driven assessment** — Claude maps each finding to controls, scores its contextual risk, and recommends a remediation through Bedrock tool use (`map_to_controls`, `score_risk`, `recommend_remediation`, `log_assessment`).
- **Control mapping** across CIS Controls v8, NIST 800-53, and SOC 2.
- **Safe by default** — dry-run and identifier masking are on unless explicitly disabled; the auditor only escalates and logs, it does not change your infrastructure.
- **Identifier masking** — resource names, ARNs, account IDs, and instance/SG IDs are replaced with deterministic, non-reversible aliases before anything leaves the tool.
- **Production-style Kubernetes deployment** — Helm chart, scheduled CronJob, hardened non-root pod, NetworkPolicy, IRSA-ready ServiceAccount.
- **Runtime security + observability** — Trivy Operator scans the workload; Prometheus + Grafana visualize run metrics.
- **Tested and linted** — `pytest` + `moto`, with `ruff` and `mypy` enforced in CI.

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
   schedule         │  Compliance pipeline (Python 3.12)          │
   (CronJob)──────► │                                             │
                    │  Scanner ─► Reasoning Engine ─► Policy/Act   │
                    │  (boto3)    (Claude / Bedrock)   (escalate/  │
                    │     │           │                log)        │
                    └─────┼───────────┼──────────────────┼─────────┘
                          ▼           ▼                   ▼
                    ┌──────────┐ ┌──────────┐   ┌──────────────────┐
                    │ AWS APIs │ │ Bedrock  │   │ GitHub Issues     │
                    │ IAM/S3/  │ │ Claude   │   │ (masked, critical)│
                    │ EC2      │ │ Haiku    │   └──────────────────┘
                    └──────────┘ └──────────┘            │
                                                  metrics ▼
                                          Pushgateway ─► Prometheus ─► Grafana
```

---

## Quick start

Prerequisites: Python 3.12, AWS credentials with read access (e.g. the managed `SecurityAudit` policy), and Bedrock model access for Claude Haiku enabled in your region.

```bash
git clone https://github.com/MiguelAngelHorta/AI-Compliance-Agent.git
cd AI-Compliance-Agent
python -m venv venv && source venv/bin/activate
pip install -e .

# Read-only scan — no changes, no AI
python -m src.main --scan --output summary
```

Add reasoning and actions as you go (actions are dry-run unless `--live` is passed):

```bash
python -m src.main --scan --reason --act --output summary
```

To escalate critical findings to GitHub Issues, set `GITHUB_REPO` and `GITHUB_TOKEN`, and set `MASK_SALT` so masked aliases are stable and unguessable:

```bash
export GITHUB_REPO="owner/repo"
export GITHUB_TOKEN="<scoped-token>"
export MASK_SALT="$(openssl rand -hex 16)"
python -m src.main --scan --reason --act --live --output summary
```

---

## Demo

The auditor runs in three stages — **scan → reason → act**. Each can run on its own or chained.

### 1. Scan

Enumerate IAM, S3, and EC2 with read-only API calls and classify findings by type and severity.

```console
$ python -m src.main --scan --output summary

[*] Running iam scanner...
    Found 0 findings
[*] Running s3 scanner...
    Found 9 findings
[*] Running ec2 scanner...
    Found 1 findings

============================================================
Scanners: iam, s3, ec2
Findings: 10
Severity: {'critical': 3, 'high': 1, 'medium': 0, 'low': 6, 'info': 0}
============================================================

🔴 [CRITICAL] Bucket 'app.example.com' does not fully block public access
   Resource: arn:aws:s3:::app.example.com
   Type: public_access

🟠 [HIGH] Security group 'launch-wizard-1' exposes SSH (port 22) to 0.0.0.0/0
   Resource: arn:aws:ec2:*:*:security-group/sg-EXAMPLE000000000
   Type: open_port

🟡 [LOW] Bucket 'example-static-assets' has no access logging
   Resource: arn:aws:s3:::example-static-assets
   Type: no_logging

   ... (7 more)
```

### 2. Reason

Each finding is sent to Claude (Bedrock) with a set of tools. The model maps the finding to compliance controls, scores its real risk in context, proposes a remediation, and logs the full reasoning chain.

```console
$ python -m src.main --scan --reason --output summary

[*] Assessing 10 findings with Claude...
  [1/10] Assessing: Bucket 'app.example.com' does not fully block public access...
    → map_to_controls       CIS-3.3, CIS-4.4 · NIST-AC-3, NIST-SC-7 · SOC2-CC6.1, SOC2-CC6.6
    → score_risk            critical  (internet-facing, 6 controls violated, likely public data)
    → recommend_remediation Enable S3 Block Public Access — set all four block settings to true
    → log_assessment        logged
  ...
```

Findings are mapped against **CIS Controls v8**, **NIST 800-53**, and **SOC 2** criteria.

### 3. Act

**Critical** findings are escalated to GitHub Issues with masked identifiers; everything else is acknowledged and logged. The auditor does not modify any AWS resources — it reviews and reports. Actions run in **dry-run mode by default**; `--live` is required before any GitHub issue is actually opened.

```console
$ python -m src.main --scan --reason --act --live

[*] Executing actions (LIVE) on 10 findings...
  [1/10] Bucket 'app.example.com' does not fully block public access
    🎫 Escalated: [CRITICAL] Bucket '<resource:6f3a9c21>' ... (masked) → GitHub issue
  [2/10] Security group 'launch-wizard-1' exposes SSH (port 22) to 0.0.0.0/0
    🎫 Escalated: [CRITICAL] Security group '<resource:1a5d44a2>' ... (masked) → GitHub issue
  [3/10] Bucket 'example-static-assets' has no access logging
    📋 Acknowledged: no_logging
  ...
[*] Actions complete
```

| Severity | Action |
|---|---|
| `critical` | 🎫 Escalate to GitHub Issues (masked) |
| `high` / `medium` / `low` | 📋 Acknowledge + log — no changes made |

> **Note:** `--live` opens real GitHub issues. Masking is on by default so resource names aren't published; run against a test account and keep `MASK_SALT` set.

### Flags

```console
--scan                 Run the scanners
--reason               Send findings to Claude for assessment
--act                  Execute actions (dry-run unless --live is set)
--dry-run / --live     Preview actions vs. apply them
--scanners iam s3 ec2  Limit which scanners run
--model haiku|sonnet   Choose the Bedrock model
--output json|summary  Output format
--no-mask              Do not mask identifiers in escalations (private trackers only)
```

---

## Deploying on Kubernetes

It ships as a hardened container and runs as a scheduled **CronJob**. A Helm chart packages the workload, and a local [Kind](https://kind.sigs.k8s.io/) setup brings up the full stack — runtime vulnerability scanning (Trivy Operator) and observability (Prometheus + Grafana) — at zero cost.

### Quick start (local, via Kind)

Prerequisites: `docker`, `kind`, `kubectl`, `helm`.

```bash
# 1. Cluster + Trivy Operator + Prometheus/Grafana + Pushgateway
./scripts/kind-setup.sh

# 2. Build, load into Kind, and deploy (dry-run mode)
export AWS_ACCESS_KEY_ID=...        # a least-privilege (SecurityAudit) key
export AWS_SECRET_ACCESS_KEY=...
export MASK_SALT=$(openssl rand -hex 16)
./scripts/kind-deploy.sh

# 3. Tear down
./scripts/kind-teardown.sh
```

The chart runs **dry-run with masking on by default** — no GitHub issues and no real identifiers leave the cluster until you opt in.

### What gets deployed

| Component | Namespace | Purpose |
|---|---|---|
| `compliance-agent` CronJob | `compliance` | The scan → reason → act pipeline on a schedule |
| Trivy Operator | `trivy-system` | Continuous vulnerability + misconfig scanning of the workload |
| kube-prometheus-stack | `monitoring` | Prometheus + Grafana |
| Prometheus Pushgateway | `monitoring` | Receives metrics from the short-lived CronJob pods |

### Observability

After each run it pushes metrics to the Pushgateway, which Prometheus scrapes and Grafana visualizes (dashboard shown above). Import `monitoring/grafana-dashboard.json` (Grafana → Dashboards → Import).

| Metric | Type | Labels |
|---|---|---|
| `compliance_findings_total` | gauge | — |
| `compliance_findings_by_severity` | gauge | `severity` |
| `compliance_findings_by_action` | gauge | `action` |
| `compliance_scan_duration_seconds` | gauge | — |
| `compliance_last_run_timestamp_seconds` | gauge | — |

The manifests are EKS-ready: the chart supports IRSA via a ServiceAccount annotation, and `values-production.yaml` documents the production overrides. The only difference between the Kind demo and EKS is where the cluster runs.

---

## How it works

**Scanners** (`src/scanner/`) use `boto3` to enumerate resources and emit typed `Finding` models (`pydantic`): IAM (wildcard actions, missing MFA, stale keys), S3 (public access, missing encryption/versioning/logging), and EC2 (security groups open to `0.0.0.0/0` on sensitive ports).

**Reasoning** (`src/reasoner/`) calls Claude Haiku through Bedrock's **Converse API** with a cross-region inference profile. Claude is given four assessment tools — `map_to_controls`, `score_risk`, `recommend_remediation`, `log_assessment` — and calls them to map the finding to controls, score its risk, and recommend a remediation. Control mappings are validated against an in-code lookup table to keep the model from inventing control IDs.

**Actions** (`src/actions/`) are decided by a deterministic policy keyed on the assessed severity: critical findings are escalated to GitHub Issues, everything else is acknowledged and logged. The LLM informs the severity; it doesn't choose or execute the action, and no AWS resource is modified. Before anything is posted to GitHub, **`src/masking/`** replaces resource names, ARNs, account IDs, and `sg-/i-/vol-`-style IDs with deterministic, non-reversible aliases (salted via `MASK_SALT`). Local console output stays unmasked for the operator.

**Metrics** (`src/metrics/`) push per-run gauges to a Pushgateway when `PUSHGATEWAY_URL` is set — best-effort, and never able to fail the run.

---

## Security posture

The project is built to pass the kind of review it performs:

- **No secrets in the repo.** Tokens and credentials are read from the environment; `.env`, `*.tfstate`, and `*.tfvars` are git-ignored. The Helm Secret is opt-in and local-demo-only.
- **Identifier masking** on all GitHub escalations, on by default.
- **Read-only and dry-run by default**; the auditor never changes AWS resources, and `--live`/`--no-mask` are explicit opt-ins.
- **Least-privilege IAM** (read-only `SecurityAudit` for scanning).
- **Hardened container**: non-root, `readOnlyRootFilesystem`, all Linux capabilities dropped, `RuntimeDefault` seccomp.
- **NetworkPolicy** denies ingress and restricts egress to DNS + HTTPS (plus the Pushgateway port when metrics are enabled).

---

## Tech stack

| Component | Technology |
|---|---|
| Runtime | Python 3.12, boto3, pydantic |
| AI reasoning | Claude Haiku via AWS Bedrock (Converse API, tool use) |
| Container | Docker (multi-stage, non-root) |
| Kubernetes | Helm chart, CronJob, Kind, IRSA-ready manifests, NetworkPolicy |
| Runtime scanning | Trivy Operator |
| Observability | Prometheus + Grafana (Pushgateway) |
| Escalation | GitHub Issues API |
| CI | GitHub Actions (ruff, mypy, pytest) |
| Testing | pytest, moto |

---

## Local development

```bash
pip install -e ".[dev]"
ruff check src/ tests/
mypy src/
pytest -q
```

CI runs the same lint → type-check → test pipeline on every push.

---

## Possible extensions

Directions this could be taken further (not implemented):

- **Automated remediation of reversible findings** — apply safe fixes (e.g. enabling S3 versioning or default encryption) automatically behind the dry-run guard, instead of only escalating and logging.
- **Production deployment on AWS Lambda** — Terraform for the function, an EventBridge schedule, IAM role, and ECR, with a build → scan → push → deploy pipeline.
- **DynamoDB-backed posture history** — persist findings and daily posture for trend analysis and a compliance score over time.
- **A React dashboard** (S3/CloudFront) reading that history — severity trends, findings drill-down, and a control-coverage heatmap.
- **Additional scanners** (RDS, Lambda) and **Slack escalation**.

---

*This is a personal project and is not affiliated with or endorsed by AWS or Anthropic.*
