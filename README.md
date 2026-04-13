# PAT Usage Audit — GitHub Organization Token Visibility

A GitHub Action and shell-based audit tool that queries multiple GitHub APIs to produce a comprehensive report of **Personal Access Token (PAT)** usage across a GitHub organization. Because GitHub does not offer a single "list all PATs" API, this tool combines SAML SSO credential authorizations, the organization audit log, and GraphQL queries to maximize visibility.

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [How It Works](#how-it-works)
- [Usage](#usage)
- [Data Sources & Coverage](#data-sources--coverage)
- [Required PAT Scope Permissions](#required-pat-scope-permissions)
- [All GitHub PAT Scopes Reference](#all-github-pat-scopes-reference)
- [Setup & Configuration](#setup--configuration)
- [Report Outputs](#report-outputs)
- [Limitations](#limitations)
- [Repository Structure](#repository-structure)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Why This Exists

GitHub does not expose a single API endpoint to enumerate **all** classic PATs (`ghp_*`) created by members of an organization. Classic PATs are user-owned; org-level visibility is limited to:

- **SAML SSO credential authorizations** — only if SAML SSO is configured on the org.
- **Audit log events** — only on **GitHub Enterprise Cloud**.
- **Fine-grained PAT management endpoints** — require a **GitHub App** installation token (not a classic PAT).

This tool bridges those gaps by aggregating every available signal into a single Markdown + JSON report.

---

## How It Works

The audit script (`scripts/pat-audit.sh`) executes the following steps in order:

1. **Authenticate & validate** the provided classic PAT against the GitHub API.
2. **Fetch all organization repositories** via GraphQL pagination.
3. **Fetch all organization members** with roles via GraphQL.
4. **Query SAML SSO credential authorizations** — lists every PAT and SSH key that has been authorized for SSO.
5. **Query the audit log for PAT lifecycle events** — creation, approval, denial, revocation.
6. **Query the audit log for token-authenticated access events** — API calls made with PATs or by bots.
7. **Build an actor summary** — unique users/bots sorted by activity volume.
8. **Generate a consolidated Markdown report** and raw JSON data files.

---

## Usage

### Run as a GitHub Action

This repository already includes a workflow at `.github/workflows/pat-audit.yml`. It:

- Runs weekly on Mondays at 08:00 UTC (and supports `workflow_dispatch` with optional org name and lookback overrides).
- Reads the PAT from `secrets.ORG_LEVEL_PAT` and the org name from `vars.GITHUB_ORG_NAME` (falls back to `github.repository_owner` automatically).
- Uploads the `reports/` directory as an artifact retained for 90 days.

```yaml
# .github/workflows/pat-audit.yml (included in this repo)
name: PAT Audit - Organization Token Inventory & Access Report

on:
  schedule:
    - cron: '0 8 * * 1'
  workflow_dispatch:
    inputs:
      org_name:
        description: 'GitHub Organization name (overrides default)'
        required: false
        type: string
      lookback_days:
        description: 'Number of days to look back in audit log'
        required: false
        default: '30'
        type: string

permissions:
  contents: read

jobs:
  pat-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run PAT Audit Script
        env:
          ORG_PAT: ${{ secrets.ORG_LEVEL_PAT }}
          ORG_NAME: ${{ inputs.org_name || vars.GITHUB_ORG_NAME || github.repository_owner }}
          LOOKBACK_DAYS: ${{ inputs.lookback_days || '30' }}
        run: |
          chmod +x ./scripts/pat-audit.sh
          ./scripts/pat-audit.sh

      - name: Upload Audit Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pat-audit-report-${{ github.run_id }}
          path: ./reports/
          retention-days: 90
```

### Run Locally

```bash
export ORG_PAT="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export ORG_NAME="your-org"
export LOOKBACK_DAYS=30

bash scripts/pat-audit.sh
```

The report will be written to `./reports/`.

---

## Data Sources & Coverage

| Data Source | API Endpoint | What It Shows | Requirements |
|---|---|---|---|
| SAML SSO Credential Authorizations | `GET /orgs/{org}/credential-authorizations` | PATs & SSH keys authorized for SSO: user, token last 8 chars, scopes, auth/access/expiry dates | SAML SSO enabled (any plan) |
| Audit Log — PAT Lifecycle | `GET /orgs/{org}/audit-log?phrase=action:personal_access_token` | Token creation, approval, denial, revocation events | Enterprise Cloud |
| Audit Log — Token Auth Events | `GET /orgs/{org}/audit-log?include=all` | API calls made via PAT/bot (actor, action, repo, access type) | Enterprise Cloud |
| Actor Summary | Aggregated from audit log | Per-user event count, bot flag, repos accessed, timeline | Enterprise Cloud |
| Repositories | GraphQL `organization.repositories` | Full repo inventory with privacy, archive status, last push | `read:org`, `repo` |
| Members | GraphQL `organization.membersWithRole` | All members with roles | `admin:org` |

### Coverage by Org Configuration

| Configuration | Classic PATs Visible? | Fine-Grained PATs Visible? | Access Events Visible? |
|---|---|---|---|
| **Enterprise Cloud + SAML SSO** | Yes — credential authorizations | Audit log + GitHub App | Yes — audit log |
| **Enterprise Cloud, no SAML** | Audit log only | Audit log + GitHub App | Yes — audit log |
| **Team/Pro + SAML SSO** | Yes — credential authorizations | GitHub App only | No audit log API |
| **Team/Pro, no SAML** | No | GitHub App only | No |
| **Free plan** | No | GitHub App only | No |

---

## Required PAT Scope Permissions

The audit script authenticates with a **classic Personal Access Token**. The following scopes are **required**:

| Scope | Permission Level | Why It's Needed |
|---|---|---|
| **`admin:org`** | Full org admin | Read SAML SSO credential authorizations (`GET /orgs/{org}/credential-authorizations`), list members with roles via GraphQL |
| **`read:audit_log`** | Read-only | Query the organization audit log for PAT lifecycle and token authentication events |
| **`read:org`** | Read-only | List organization details and membership |
| **`repo`** | Full repo access | Access metadata for **private** repositories in the org inventory |

> **Note:** `admin:org` is a parent scope that implicitly includes `read:org` and `write:org`. It is required because the credential-authorizations endpoint demands admin-level access.

---

## All GitHub PAT Scopes Reference

Below is a comprehensive reference of **all available classic PAT scopes** on GitHub, indicating which ones this tool uses and which are not needed.

### Scopes Used by This Tool

| Scope | Sub-scope | Description | Used Here? |
|---|---|---|---|
| **`repo`** | — | Full control of private repositories | **Yes** |
| | `repo:status` | Access commit status | Included via `repo` |
| | `repo_deployment` | Access deployment status | Included via `repo` |
| | `public_repo` | Access public repositories | Included via `repo` |
| | `repo:invite` | Access repository invitations | Included via `repo` |
| | `security_events` | Read/write security events | Included via `repo` |
| **`admin:org`** | — | Full control of orgs and teams | **Yes** |
| | `write:org` | Read and write org membership | Included via `admin:org` |
| | `read:org` | Read org membership | Included via `admin:org` |
| | `manage_runners:org` | Manage org runners | Included via `admin:org` |
| **`audit_log`** | — | Full control of audit log | — |
| | `read:audit_log` | Read audit log | **Yes** |

### Scopes NOT Used by This Tool

These scopes exist on GitHub but are **not required** for PAT auditing:

| Scope | Sub-scope | Description | Why Not Needed |
|---|---|---|---|
| **`workflow`** | — | Update GitHub Action workflows | No workflow modification performed |
| **`write:packages`** | — | Upload packages to GitHub Packages | No package operations |
| | `read:packages` | Download packages | No package operations |
| **`delete:packages`** | — | Delete packages | No package operations |
| **`admin:public_key`** | — | Full control of user public keys | SSH key audit uses credential-authorizations instead |
| | `write:public_key` | Create public keys | Not needed |
| | `read:public_key` | List public keys | Not needed |
| **`admin:repo_hook`** | — | Full control of repository hooks | No webhook operations |
| | `write:repo_hook` | Write repository hooks | Not needed |
| | `read:repo_hook` | Read repository hooks | Not needed |
| **`admin:org_hook`** | — | Full control of organization hooks | No webhook operations |
| **`gist`** | — | Create gists | No gist operations |
| **`notifications`** | — | Access notifications | No notification operations |
| **`user`** | — | Update all user data | Only `GET /user` is called (no scope needed) |
| | `read:user` | Read user profile data | Implicit with any token |
| | `user:email` | Access user email addresses | Not needed |
| | `user:follow` | Follow and unfollow users | Not needed |
| **`delete_repo`** | — | Delete repositories | No repository deletion |
| **`write:discussion`** | — | Read and write team discussions | No discussion operations |
| | `read:discussion` | Read team discussions | Not needed |
| **`admin:enterprise`** | — | Full control of enterprises | Not needed (org-level only) |
| | `manage_runners:enterprise` | Manage enterprise runners | Not needed |
| | `manage_billing:enterprise` | Read enterprise billing | Not needed |
| | `read:enterprise` | Read enterprise profile | Not needed |
| **`admin:gpg_key`** | — | Full control of GPG keys | No GPG key operations |
| | `write:gpg_key` | Create GPG keys | Not needed |
| | `read:gpg_key` | List GPG keys | Not needed |
| **`codespace`** | — | Full control of codespaces | No codespace operations |
| **`copilot`** | — | Manage Copilot settings | No Copilot operations |
| **`project`** | — | Full control of projects | No project operations |
| | `read:project` | Read projects | Not needed |
| **`admin:ssh_signing_key`** | — | Full control of SSH signing keys | Not needed |
| | `write:ssh_signing_key` | Create SSH signing keys | Not needed |
| | `read:ssh_signing_key` | List SSH signing keys | Not needed |

---

## Setup & Configuration

### 1. Create the Classic PAT

1. Go to [GitHub Settings → Developer Settings → Personal Access Tokens → Tokens (classic)](https://github.com/settings/tokens).
2. Click **Generate new token (classic)**.
3. Select the following scopes:
   - `admin:org`
   - `read:audit_log`
   - `repo`
4. Set an appropriate expiration (recommend 90 days max).
5. Copy the generated token.

### 2. Configure Repository Secrets & Variables

In the repository running this action:

| Secret / Variable | Type | Value |
|---|---|---|
| `ORG_LEVEL_PAT` | **Secret** | The classic PAT created above |
| `GITHUB_ORG_NAME` | **Variable** | Your GitHub organization slug (e.g., `octodemo`) |

### 3. Environment Variables

The audit script uses the following environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `ORG_PAT` | Yes | — | Classic PAT with the required scopes |
| `ORG_NAME` | Yes | — | GitHub organization slug |
| `LOOKBACK_DAYS` | No | `30` | Number of days to look back in the audit log |
| `GITHUB_API_VERSION` | No | `2026-03-10` | GitHub API version header |

---

## Report Outputs

After execution, the `reports/` directory contains:

| File | Format | Description |
|---|---|---|
| `pat-audit-report.md` | Markdown | Human-readable consolidated report with all sections |
| `repositories.json` | JSON | All org repositories with metadata (name, privacy, archive status, timestamps) |
| `members.json` | JSON | All org members with roles and account creation dates |
| `credential_authorizations.json` | JSON | SAML SSO authorized credentials (PATs + SSH keys) |
| `audit_pat_events.json` | JSON | Audit log events for PAT lifecycle (create, approve, deny, revoke) |
| `audit_token_access.json` | JSON | Audit log events with token-based authentication markers |
| `actor_summary.json` | JSON | Aggregated per-actor activity summary |

---

## Limitations

1. **No universal PAT listing** — There is no GitHub API to list all classic PATs across an organization. Coverage depends on SAML SSO and Enterprise Cloud.
2. **Fine-grained PAT enumeration requires a GitHub App** — The `/orgs/{org}/personal-access-tokens` endpoint does not accept classic PATs for authentication.
3. **Audit log requires Enterprise Cloud** — Free and Team plans do not have API access to the audit log.
4. **Token values are never exposed** — The audit log shows `token_last_eight` or `hashed_token`, never the full token (by design).
5. **SAML SSO credential authorizations require SAML** — If your org doesn't use SAML SSO, this data source returns nothing.
6. **Rate limits** — Large organizations may hit GitHub API rate limits. The script uses pagination with safety limits (max 50 pages per endpoint).

---

## Repository Structure

```
PatUsage/
├── .github/
│   └── workflows/
│       └── pat-audit.yml      # GitHub Actions workflow (scheduled + manual)
├── README.md                  # This file
├── FEASIBILITY-REVIEW.md      # Detailed API feasibility analysis and setup guide
├── scripts/
│   └── pat-audit.sh           # Main audit script (bash)
└── reports/
    └── .gitkeep               # Placeholder (reports generated at runtime)
```

---

## Security Considerations

- **Store the PAT as an encrypted repository secret** — never commit it to the repository.
- **Use a dedicated service account** — avoid using a personal PAT with broad access.
- **Rotate the PAT regularly** — set a short expiration (90 days or less) and rotate on schedule.
- **Principle of least privilege** — the required scopes (`admin:org`, `read:audit_log`, `repo`) are broad; restrict the service account's org role to the minimum needed.
- **Report artifacts may contain sensitive metadata** — restrict access to workflow artifacts and avoid publishing reports publicly.

---

## License

This project is provided as-is for internal organizational use.
