#!/usr/bin/env bash
# =============================================================================
# PAT Audit Script for GitHub Organizations
# =============================================================================
# Queries GitHub REST & GraphQL APIs to produce a comprehensive report of:
#   1. Fine-grained PATs with org access (SAML SSO credential authorizations)
#   2. Audit log events related to PAT usage (who accessed what, when)
#   3. Organization repositories inventory
#   4. Org member list for cross-referencing
#
# Required environment variables:
#   ORG_PAT       - A classic PAT with scopes: admin:org, read:audit_log, read:org, repo
#   ORG_NAME      - The GitHub organization slug
#   LOOKBACK_DAYS - How many days back to scan the audit log (default: 30)
#
# Required PAT scopes (classic PAT):
#   - admin:org       (for credential-authorizations / SAML SSO)
#   - read:audit_log  (for audit log queries)
#   - read:org        (for listing members, repos)
#   - repo            (for listing all repos including private)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE="https://api.github.com"
GRAPHQL_URL="https://api.github.com/graphql"
API_VERSION="${GITHUB_API_VERSION:-2026-03-10}"

if [[ -z "${ORG_PAT:-}" ]]; then
  echo "::error::ORG_PAT secret is not set. Please configure it in repository secrets."
  exit 1
fi

if [[ -z "${ORG_NAME:-}" ]]; then
  echo "::error::ORG_NAME is not set. Provide it via vars.GITHUB_ORG_NAME or workflow input."
  exit 1
fi

LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"
REPORT_DIR="./reports"
mkdir -p "$REPORT_DIR"

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOOKBACK_DATE="$(date -u -d "${LOOKBACK_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-"${LOOKBACK_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)"

echo "============================================"
echo "  PAT Audit Report for: ${ORG_NAME}"
echo "  Generated: ${TIMESTAMP}"
echo "  Lookback:  ${LOOKBACK_DAYS} days (since ${LOOKBACK_DATE})"
echo "============================================"

# ---------------------------------------------------------------------------
# Helper: authenticated curl for REST
# ---------------------------------------------------------------------------
gh_rest() {
  local method="${1}"
  local endpoint="${2}"
  shift 2
  curl -fsSL \
    -X "${method}" \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${ORG_PAT}" \
    -H "X-GitHub-Api-Version: ${API_VERSION}" \
    "$@" \
    "${API_BASE}${endpoint}"
}

# ---------------------------------------------------------------------------
# Helper: authenticated curl for GraphQL
# ---------------------------------------------------------------------------
gh_graphql() {
  local query="${1}"
  curl -fsSL \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${ORG_PAT}" \
    "${GRAPHQL_URL}" \
    -d "${query}"
}

# ---------------------------------------------------------------------------
# Helper: paginated REST fetch (collects all pages into a JSON array)
# ---------------------------------------------------------------------------
gh_rest_paginated() {
  local endpoint="${1}"
  local per_page="${2:-100}"
  local results="[]"
  local page=1
  local max_pages=50  # safety limit

  while [[ $page -le $max_pages ]]; do
    local separator="?"
    if [[ "${endpoint}" == *"?"* ]]; then
      separator="&"
    fi
    local response
    response="$(gh_rest GET "${endpoint}${separator}per_page=${per_page}&page=${page}" 2>/dev/null || echo "[]")"

    # Check if response is empty array or error
    local count
    count="$(echo "${response}" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo "0")"

    if [[ "${count}" -eq 0 ]]; then
      break
    fi

    results="$(echo "${results}" "${response}" | jq -s '.[0] + .[1]')"
    page=$((page + 1))

    if [[ "${count}" -lt "${per_page}" ]]; then
      break
    fi
  done

  echo "${results}"
}

# =============================================================================
# SECTION 1: Validate PAT & Verify Authentication
# =============================================================================
echo ""
echo ">> Step 1: Validating PAT authentication..."

AUTH_CHECK="$(gh_rest GET "/user" 2>/dev/null || echo "{}")"
AUTH_USER="$(echo "${AUTH_CHECK}" | jq -r '.login // "UNKNOWN"')"

if [[ "${AUTH_USER}" == "UNKNOWN" ]]; then
  echo "::error::Failed to authenticate with the provided PAT."
  exit 1
fi

echo "   Authenticated as: ${AUTH_USER}"

# Verify org access
ORG_INFO="$(gh_rest GET "/orgs/${ORG_NAME}" 2>/dev/null || echo "{}")"
ORG_ID="$(echo "${ORG_INFO}" | jq -r '.id // "UNKNOWN"')"

if [[ "${ORG_ID}" == "UNKNOWN" ]]; then
  echo "::error::Cannot access organization '${ORG_NAME}'. Check PAT scopes and org membership."
  exit 1
fi

echo "   Organization: ${ORG_NAME} (ID: ${ORG_ID})"

# =============================================================================
# SECTION 2: List Organization Repositories (via GraphQL)
# =============================================================================
echo ""
echo ">> Step 2: Fetching organization repositories via GraphQL..."

REPOS_FILE="${REPORT_DIR}/repositories.json"
ALL_REPOS="[]"
HAS_NEXT="true"
CURSOR=""

while [[ "${HAS_NEXT}" == "true" ]]; do
  AFTER_CLAUSE=""
  if [[ -n "${CURSOR}" ]]; then
    AFTER_CLAUSE=", after: \\\"${CURSOR}\\\""
  fi

  GRAPHQL_QUERY="{\"query\": \"query { organization(login: \\\"${ORG_NAME}\\\") { repositories(first: 100${AFTER_CLAUSE}) { pageInfo { hasNextPage endCursor } nodes { name nameWithOwner isPrivate isArchived createdAt updatedAt pushedAt } } } }\"}"

  RESPONSE="$(gh_graphql "${GRAPHQL_QUERY}" 2>/dev/null || echo "{}")"

  REPOS_BATCH="$(echo "${RESPONSE}" | jq '.data.organization.repositories.nodes // []')"
  ALL_REPOS="$(echo "${ALL_REPOS}" "${REPOS_BATCH}" | jq -s '.[0] + .[1]')"

  HAS_NEXT="$(echo "${RESPONSE}" | jq -r '.data.organization.repositories.pageInfo.hasNextPage // false')"
  CURSOR="$(echo "${RESPONSE}" | jq -r '.data.organization.repositories.pageInfo.endCursor // empty')"
done

REPO_COUNT="$(echo "${ALL_REPOS}" | jq 'length')"
echo "   Found ${REPO_COUNT} repositories"
echo "${ALL_REPOS}" | jq '.' > "${REPOS_FILE}"

# =============================================================================
# SECTION 3: List Organization Members (via GraphQL)
# =============================================================================
echo ""
echo ">> Step 3: Fetching organization members via GraphQL..."

MEMBERS_FILE="${REPORT_DIR}/members.json"
ALL_MEMBERS="[]"
HAS_NEXT="true"
CURSOR=""

while [[ "${HAS_NEXT}" == "true" ]]; do
  AFTER_CLAUSE=""
  if [[ -n "${CURSOR}" ]]; then
    AFTER_CLAUSE=", after: \\\"${CURSOR}\\\""
  fi

  GRAPHQL_QUERY="{\"query\": \"query { organization(login: \\\"${ORG_NAME}\\\") { membersWithRole(first: 100${AFTER_CLAUSE}) { pageInfo { hasNextPage endCursor } nodes { login name email createdAt } edges { role } } } }\"}"

  RESPONSE="$(gh_graphql "${GRAPHQL_QUERY}" 2>/dev/null || echo "{}")"

  MEMBERS_BATCH="$(echo "${RESPONSE}" | jq '[.data.organization.membersWithRole as $m | range($m.nodes | length) | {login: $m.nodes[.].login, name: $m.nodes[.].name, email: $m.nodes[.].email, role: $m.edges[.].role, createdAt: $m.nodes[.].createdAt}] // []')"
  ALL_MEMBERS="$(echo "${ALL_MEMBERS}" "${MEMBERS_BATCH}" | jq -s '.[0] + .[1]')"

  HAS_NEXT="$(echo "${RESPONSE}" | jq -r '.data.organization.membersWithRole.pageInfo.hasNextPage // false')"
  CURSOR="$(echo "${RESPONSE}" | jq -r '.data.organization.membersWithRole.pageInfo.endCursor // empty')"
done

MEMBER_COUNT="$(echo "${ALL_MEMBERS}" | jq 'length')"
echo "   Found ${MEMBER_COUNT} members"
echo "${ALL_MEMBERS}" | jq '.' > "${MEMBERS_FILE}"

# =============================================================================
# SECTION 4: SAML SSO Credential Authorizations (PATs & SSH Keys)
# Endpoint: GET /orgs/{org}/credential-authorizations
# Works with classic PAT (read:org) or fine-grained PAT (Administration: read)
# Available on ALL plans — requires SAML SSO to be configured on the org
# Supports ?login= filter to narrow by specific user
# Response includes: login, credential_id, credential_type, token_last_eight,
#   credential_authorized_at, credential_accessed_at, authorized_credential_expires_at, scopes
# =============================================================================
echo ""
echo ">> Step 4: Fetching SAML SSO credential authorizations..."
echo "   (Available on all plans; requires SAML SSO enabled on org)"

CREDS_FILE="${REPORT_DIR}/credential_authorizations.json"
CREDS_DATA="$(gh_rest_paginated "/orgs/${ORG_NAME}/credential-authorizations" 100 2>/dev/null || echo "[]")"

# Filter to PATs only
PAT_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "personal access token")]' 2>/dev/null || echo "[]")"
PAT_CRED_COUNT="$(echo "${PAT_CREDS}" | jq 'length')"

echo "   Found ${PAT_CRED_COUNT} authorized PATs via SAML SSO"

# Also count SSH keys and other credential types
SSH_CREDS="$(echo "${CREDS_DATA}" | jq '[.[] | select(.credential_type == "SSH key")]' 2>/dev/null || echo "[]")"
SSH_CRED_COUNT="$(echo "${SSH_CREDS}" | jq 'length')"
TOTAL_CRED_COUNT="$(echo "${CREDS_DATA}" | jq 'length' 2>/dev/null || echo "0")"

echo "   Found ${SSH_CRED_COUNT} authorized SSH keys via SAML SSO"
echo "   Total credentials: ${TOTAL_CRED_COUNT}"

echo "${CREDS_DATA}" | jq '.' > "${CREDS_FILE}"

# =============================================================================
# SECTION 5: Audit Log - PAT-related Events
# =============================================================================
echo ""
echo ">> Step 5: Querying audit log for PAT-related events..."

AUDIT_PAT_FILE="${REPORT_DIR}/audit_pat_events.json"

# Search for personal access token events in audit log
# Key audit actions for PATs:
#   - personal_access_token.access_granted
#   - personal_access_token.access_denied
#   - personal_access_token.request_created
#   - personal_access_token.request_cancelled
#   - personal_access_token.access_revoked
#   - personal_access_token.credential_regenerated

PAT_AUDIT_EVENTS="[]"
AUDIT_PHRASES=(
  "action:personal_access_token created:>=${LOOKBACK_DATE}"
  "action:personal_access_token. created:>=${LOOKBACK_DATE}"
)

for phrase in "${AUDIT_PHRASES[@]}"; do
  ENCODED_PHRASE="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${phrase}'))" 2>/dev/null || echo "${phrase}")"
  EVENTS="$(gh_rest_paginated "/orgs/${ORG_NAME}/audit-log?phrase=${ENCODED_PHRASE}&include=all" 100 2>/dev/null || echo "[]")"
  EVENT_COUNT="$(echo "${EVENTS}" | jq 'length' 2>/dev/null || echo "0")"
  if [[ "${EVENT_COUNT}" -gt 0 ]]; then
    PAT_AUDIT_EVENTS="$(echo "${PAT_AUDIT_EVENTS}" "${EVENTS}" | jq -s '.[0] + .[1] | unique_by(._document_id // .["@timestamp"])')"
    break  # Found events with this phrase pattern
  fi
done

PAT_AUDIT_COUNT="$(echo "${PAT_AUDIT_EVENTS}" | jq 'length')"
echo "   Found ${PAT_AUDIT_COUNT} PAT-related audit log events"
echo "${PAT_AUDIT_EVENTS}" | jq '.' > "${AUDIT_PAT_FILE}"

# =============================================================================
# SECTION 6: Audit Log - Token Authentication Events
# =============================================================================
echo ""
echo ">> Step 6: Querying audit log for token-based authentication events..."

AUDIT_AUTH_FILE="${REPORT_DIR}/audit_token_access.json"

# Search for programmatic (token-based) access patterns
# These include: API calls made with PATs showing actor + action + repo
TOKEN_ACCESS_EVENTS="$(gh_rest_paginated "/orgs/${ORG_NAME}/audit-log?phrase=created:>=${LOOKBACK_DATE}&include=all" 100 2>/dev/null || echo "[]")"

# Filter for events that have programmatic_access_type or token-related fields
TOKEN_AUTH_EVENTS="$(echo "${TOKEN_ACCESS_EVENTS}" | jq '[.[] | select(
  .programmatic_access_type != null or
  .token_id != null or
  .hashed_token != null or
  .credential_authorized_at != null or
  (.actor_is_bot == true)
)]' 2>/dev/null || echo "[]")"

TOKEN_AUTH_COUNT="$(echo "${TOKEN_AUTH_EVENTS}" | jq 'length')"
echo "   Found ${TOKEN_AUTH_COUNT} token-authenticated audit events"
echo "${TOKEN_AUTH_EVENTS}" | jq '.' > "${AUDIT_AUTH_FILE}"

# =============================================================================
# SECTION 7: Audit Log - Actor Summary (users/bots using PATs)
# =============================================================================
echo ""
echo ">> Step 7: Building actor access summary from audit log..."

ACTOR_SUMMARY_FILE="${REPORT_DIR}/actor_summary.json"

# Summarize all audit events by actor to identify who is making API calls
ACTOR_SUMMARY="$(echo "${TOKEN_ACCESS_EVENTS}" | jq '
  group_by(.actor) |
  map({
    actor: .[0].actor,
    total_events: length,
    actions: ([.[].action] | unique),
    first_seen: ([.[]."@timestamp"] | min | . / 1000 | todate),
    last_seen: ([.[]."@timestamp"] | max | . / 1000 | todate),
    repos_accessed: ([.[].repo // empty] | unique),
    has_programmatic_access: (any(.programmatic_access_type != null)),
    is_bot: (any(.actor_is_bot == true))
  }) |
  sort_by(-.total_events)
' 2>/dev/null || echo "[]")"

ACTOR_COUNT="$(echo "${ACTOR_SUMMARY}" | jq 'length')"
echo "   Identified ${ACTOR_COUNT} unique actors in audit log"
echo "${ACTOR_SUMMARY}" | jq '.' > "${ACTOR_SUMMARY_FILE}"

# =============================================================================
# SECTION 8: Workflow PAT Scanner
# Scans all org repos for workflow files that reference secrets other than
# GITHUB_TOKEN — indicating a user-created PAT or custom token is in use.
# Uses GitHub Code Search API for efficiency.
# =============================================================================
echo ""
echo ">> Step 8: Scanning org workflows for PAT/secret usage..."

WORKFLOW_SECRETS_FILE="${REPORT_DIR}/workflow_secrets.json"

# Use code search to find workflow files referencing secrets
SEARCH_RESULTS="[]"
SEARCH_PAGE=1
SEARCH_MAX_PAGES=10

while [[ $SEARCH_PAGE -le $SEARCH_MAX_PAGES ]]; do
  SEARCH_RESPONSE="$(gh_rest GET "/search/code?q=secrets.+org:${ORG_NAME}+path:.github/workflows+language:yaml&per_page=100&page=${SEARCH_PAGE}" 2>/dev/null || echo '{"items":[]}')"

  SEARCH_BATCH="$(echo "${SEARCH_RESPONSE}" | jq '.items // []')"
  BATCH_COUNT="$(echo "${SEARCH_BATCH}" | jq 'length')"

  if [[ "${BATCH_COUNT}" -eq 0 ]]; then
    break
  fi

  SEARCH_RESULTS="$(echo "${SEARCH_RESULTS}" "${SEARCH_BATCH}" | jq -s '.[0] + .[1]')"
  SEARCH_PAGE=$((SEARCH_PAGE + 1))

  # Code search rate limit: pause briefly between pages
  sleep 2

  if [[ "${BATCH_COUNT}" -lt 100 ]]; then
    break
  fi
done

# For each matched file, fetch content and extract secret names
WORKFLOW_SECRETS="[]"
PROCESSED_FILES="[]"

# Get unique repo+path combinations
UNIQUE_FILES="$(echo "${SEARCH_RESULTS}" | jq -r '[.[] | {repo: .repository.full_name, path: .path, html_url: .html_url}] | unique_by(.repo + .path)')"
UNIQUE_FILE_COUNT="$(echo "${UNIQUE_FILES}" | jq 'length')"

echo "   Found ${UNIQUE_FILE_COUNT} workflow files referencing secrets"

# Process each file (limit to 200 to avoid rate limits)
PROCESS_LIMIT=200
PROCESSED=0

echo "${UNIQUE_FILES}" | jq -c '.[0:200] | .[]' 2>/dev/null | while IFS= read -r file_info; do
  REPO_FULL="$(echo "${file_info}" | jq -r '.repo')"
  FILE_PATH="$(echo "${file_info}" | jq -r '.path')"

  # Fetch file content via Contents API
  FILE_CONTENT="$(gh_rest GET "/repos/${REPO_FULL}/contents/${FILE_PATH}" 2>/dev/null || echo '{}')"
  DECODED="$(echo "${FILE_CONTENT}" | jq -r '.content // ""' | base64 -d 2>/dev/null || echo "")"

  if [[ -z "${DECODED}" ]]; then
    continue
  fi

  # Extract all secrets.XXXX references, excluding GITHUB_TOKEN and github.token
  SECRET_NAMES="$(echo "${DECODED}" | grep -oE 'secrets\.[A-Za-z_][A-Za-z0-9_]*' | sed 's/secrets\.//' | sort -u | grep -iv '^GITHUB_TOKEN$' || true)"

  if [[ -n "${SECRET_NAMES}" ]]; then
    # Build JSON array of secret names
    SECRET_JSON="$(echo "${SECRET_NAMES}" | jq -R -s 'split("\n") | map(select(length > 0))')"

    # Extract env var mappings: ENV_VAR: ${{ secrets.XXX }} patterns
    ENV_MAPPINGS="$(echo "${DECODED}" | grep -E '^\s+\w+:.*\$\{\{\s*secrets\.' | sed 's/^[[:space:]]*//' | head -20 || true)"
    ENV_JSON="$(echo "${ENV_MAPPINGS}" | jq -R -s 'split("\n") | map(select(length > 0))')"

    echo "{\"repo\": \"${REPO_FULL}\", \"workflow\": \"${FILE_PATH}\", \"secrets\": ${SECRET_JSON}, \"env_mappings\": ${ENV_JSON}}" >> "${REPORT_DIR}/_wf_tmp.jsonl"
  fi

  PROCESSED=$((PROCESSED + 1))
  # Brief pause every 10 files to avoid rate limiting
  if [[ $((PROCESSED % 10)) -eq 0 ]]; then
    sleep 1
  fi
done

# Consolidate workflow secrets data
if [[ -f "${REPORT_DIR}/_wf_tmp.jsonl" ]]; then
  WORKFLOW_SECRETS="$(cat "${REPORT_DIR}/_wf_tmp.jsonl" | jq -s '.' 2>/dev/null || echo "[]")"
  rm -f "${REPORT_DIR}/_wf_tmp.jsonl"
else
  WORKFLOW_SECRETS="[]"
fi

WORKFLOW_SECRET_COUNT="$(echo "${WORKFLOW_SECRETS}" | jq 'length')"
echo "   Found ${WORKFLOW_SECRET_COUNT} workflows using custom secrets (non-GITHUB_TOKEN)"
echo "${WORKFLOW_SECRETS}" | jq '.' > "${WORKFLOW_SECRETS_FILE}"

# =============================================================================
# SECTION 9: Per-User PAT Activity Matrix
# Cross-references all data sources to build a per-user view:
#   - Which repos the user accessed with a PAT (from audit log)
#   - Which repos contain workflows referencing secrets (possible PAT usage)
#   - SAML SSO credential info
# =============================================================================
echo ""
echo ">> Step 9: Building per-user PAT activity matrix..."

USER_PAT_MATRIX_FILE="${REPORT_DIR}/user_pat_matrix.json"

# Build per-user PAT access from audit log (non-bot actors with token indicators)
USER_PAT_ACCESS="$(echo "${TOKEN_ACCESS_EVENTS}" | jq '
  [.[] | select(
    (.actor_is_bot != true) and
    (.programmatic_access_type != null or .hashed_token != null or .token_id != null)
  )] |
  group_by(.actor) |
  map({
    user: .[0].actor,
    repos_accessed_with_pat: ([.[].repo // empty] | unique),
    token_types_used: ([.[].programmatic_access_type // empty] | unique),
    actions_performed: ([.[].action] | unique),
    event_count: length,
    first_activity: ([.[]."@timestamp"] | min | . / 1000 | todate),
    last_activity: ([.[]."@timestamp"] | max | . / 1000 | todate)
  }) |
  sort_by(-.event_count)
' 2>/dev/null || echo "[]")"

# Merge with SAML SSO credential data
USER_PAT_MATRIX="$(echo "${USER_PAT_ACCESS}" | jq --argjson creds "${PAT_CREDS}" --argjson wf "${WORKFLOW_SECRETS}" '
  # Build lookup of SAML credentials by user
  ($creds | group_by(.login) | map({key: .[0].login, value: .}) | from_entries) as $cred_map |
  # Build lookup of workflow secrets by repo
  ($wf | group_by(.repo) | map({key: .[0].repo, value: [.[].secrets[]] | unique}) | from_entries) as $wf_map |
  # Get all unique users from all sources
  (
    [.[].user] +
    [$creds[].login // empty] +
    [keys[]]
  ) | unique | map(select(. != null and . != "")) |
  # Build matrix for each user
  map(. as $user |
    {
      user: $user,
      repos_accessed_with_pat: (
        [($[] | select(.user == $user))][0].repos_accessed_with_pat // []
      ),
      token_types_used: (
        [($[] | select(.user == $user))][0].token_types_used // []
      ),
      actions_performed: (
        [($[] | select(.user == $user))][0].actions_performed // []
      ),
      audit_event_count: (
        [($[] | select(.user == $user))][0].event_count // 0
      ),
      first_activity: (
        [($[] | select(.user == $user))][0].first_activity // null
      ),
      last_activity: (
        [($[] | select(.user == $user))][0].last_activity // null
      ),
      saml_pats: (
        [$cred_map[$user] // [] | .[] | {
          token_last_eight: .token_last_eight,
          scopes: (.scopes | join(", ")),
          last_accessed: (.credential_accessed_at // "Never"),
          expires: (.authorized_credential_expires_at // "Never")
        }]
      ),
      repos_with_user_workflows: (
        [$wf[] | select(.secrets | length > 0) | .repo] | unique
      )
    }
  ) |
  sort_by(-.audit_event_count)
' 2>/dev/null || echo "${USER_PAT_ACCESS}")"

# Simpler fallback if the complex merge fails
if [[ "$(echo "${USER_PAT_MATRIX}" | jq 'length' 2>/dev/null || echo 0)" -eq 0 ]] && [[ "$(echo "${USER_PAT_ACCESS}" | jq 'length' 2>/dev/null || echo 0)" -gt 0 ]]; then
  USER_PAT_MATRIX="${USER_PAT_ACCESS}"
fi

USER_MATRIX_COUNT="$(echo "${USER_PAT_MATRIX}" | jq 'length' 2>/dev/null || echo "0")"
echo "   Built activity matrix for ${USER_MATRIX_COUNT} users"
echo "${USER_PAT_MATRIX}" | jq '.' > "${USER_PAT_MATRIX_FILE}"

# =============================================================================
# SECTION 10: Generate Consolidated Report
# =============================================================================
echo ""
echo ">> Step 10: Generating consolidated report..."

REPORT_FILE="${REPORT_DIR}/pat-audit-report.md"

cat > "${REPORT_FILE}" << REPORT_HEADER
# PAT Audit Report: ${ORG_NAME}

**Generated:** ${TIMESTAMP}
**Authenticated As:** ${AUTH_USER}
**Lookback Period:** ${LOOKBACK_DAYS} days (since ${LOOKBACK_DATE})
**Organization ID:** ${ORG_ID}

---

## Summary

| Metric | Count |
|--------|-------|
| Total Repositories | ${REPO_COUNT} |
| Total Members | ${MEMBER_COUNT} |
| SAML SSO Authorized PATs | ${PAT_CRED_COUNT} |
| SAML SSO Authorized SSH Keys | ${SSH_CRED_COUNT} |
| PAT-Related Audit Events | ${PAT_AUDIT_COUNT} |
| Token Auth Audit Events | ${TOKEN_AUTH_COUNT} |
| Unique Actors in Audit Log | ${ACTOR_COUNT} |

---

## 1. SAML SSO Authorized Personal Access Tokens

These are PATs that have been authorized for SAML SSO access to the organization.
This section is only populated if your organization uses SAML SSO.

REPORT_HEADER

if [[ "${PAT_CRED_COUNT}" -gt 0 ]]; then
  echo "| User | Credential ID | Token (last 8) | Authorized At | Last Accessed | Expires At | Scopes |" >> "${REPORT_FILE}"
  echo "|------|--------------|-----------------|---------------|---------------|------------|--------|" >> "${REPORT_FILE}"

  echo "${PAT_CREDS}" | jq -r '.[] | "| \(.login) | \(.credential_id) | `\(.token_last_eight)` | \(.credential_authorized_at) | \(.credential_accessed_at // "Never") | \(.authorized_credential_expires_at // "Never") | \(.scopes | join(", ")) |"' >> "${REPORT_FILE}"
else
  echo "_No SAML SSO authorized PATs found. This is expected if the organization does not use SAML SSO._" >> "${REPORT_FILE}"
  echo "" >> "${REPORT_FILE}"
  echo "> **Note:** If your org does not use SAML SSO, PATs (classic) cannot be enumerated" >> "${REPORT_FILE}"
  echo "> via API. Use the audit log sections below for visibility into PAT usage." >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION2'

---

## 2. PAT-Related Audit Log Events

Events from the organization audit log related to personal access token lifecycle
(creation, approval, denial, revocation).

SECTION2

if [[ "${PAT_AUDIT_COUNT}" -gt 0 ]]; then
  echo "| Timestamp | Action | Actor | User | Details |" >> "${REPORT_FILE}"
  echo "|-----------|--------|-------|------|---------|" >> "${REPORT_FILE}"

  echo "${PAT_AUDIT_EVENTS}" | jq -r '.[] | "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | \(.action) | \(.actor // "N/A") | \(.user // "N/A") | \(.repo // .org // "—") |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No PAT-related audit events found in the last ${LOOKBACK_DAYS} days._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION3'

---

## 3. Token-Authenticated Access Events

Audit log entries identified as token-based (programmatic) access, indicating
a PAT or bot was used.

SECTION3

if [[ "${TOKEN_AUTH_COUNT}" -gt 0 ]]; then
  echo "| Timestamp | Action | Actor | Repository | Access Type |" >> "${REPORT_FILE}"
  echo "|-----------|--------|-------|------------|-------------|" >> "${REPORT_FILE}"

  echo "${TOKEN_AUTH_EVENTS}" | jq -r '.[0:200] | .[] | "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | \(.action) | \(.actor // "N/A") | \(.repo // "N/A") | \(.programmatic_access_type // "token") |"' >> "${REPORT_FILE}" 2>/dev/null || true

  if [[ "${TOKEN_AUTH_COUNT}" -gt 200 ]]; then
    echo "" >> "${REPORT_FILE}"
    echo "_Showing first 200 of ${TOKEN_AUTH_COUNT} events. See \`audit_token_access.json\` for full data._" >> "${REPORT_FILE}"
  fi
else
  echo "_No token-authenticated audit events found in the last ${LOOKBACK_DAYS} days._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION4'

---

## 4. Actor Summary (Users & Bots Accessing via API)

Unique actors observed in the audit log, sorted by activity volume.
Actors flagged as bots or with programmatic access are highlighted.

SECTION4

if [[ "${ACTOR_COUNT}" -gt 0 ]]; then
  echo "| Actor | Events | Bot? | Programmatic? | First Seen | Last Seen | Repos Accessed | Actions |" >> "${REPORT_FILE}"
  echo "|-------|--------|------|---------------|------------|-----------|----------------|---------|" >> "${REPORT_FILE}"

  echo "${ACTOR_SUMMARY}" | jq -r '.[] | "| \(.actor) | \(.total_events) | \(if .is_bot then "Yes" else "No" end) | \(if .has_programmatic_access then "Yes" else "No" end) | \(.first_seen) | \(.last_seen) | \(.repos_accessed | length) | \(.actions | length) unique |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No actors found in audit log for the specified period._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION5'

---

## 5. Workflows Using Custom Secrets (PAT Detection)

Workflows across the organization that reference secrets other than `GITHUB_TOKEN`,
indicating a user-created PAT or custom token may be in use.

SECTION5

if [[ "${WORKFLOW_SECRET_COUNT}" -gt 0 ]]; then
  echo "| Repository | Workflow File | Secrets Referenced |" >> "${REPORT_FILE}"
  echo "|-----------|--------------|-------------------|" >> "${REPORT_FILE}"

  echo "${WORKFLOW_SECRETS}" | jq -r '.[] | "| \(.repo) | `\(.workflow)` | \(.secrets | map("`\(.)`") | join(", ")) |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No workflows found using custom secrets (non-GITHUB_TOKEN)._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION6'

---

## 6. Per-User PAT Activity Matrix

Shows each user's PAT footprint: repos accessed with a token, token types used,
SAML-authorized PATs, and repos containing workflows that use custom secrets.

SECTION6

if [[ "${USER_MATRIX_COUNT}" -gt 0 ]]; then
  echo "| User | Repos Accessed via PAT | Token Types | Events | First Active | Last Active |" >> "${REPORT_FILE}"
  echo "|------|----------------------|-------------|--------|-------------|-------------|" >> "${REPORT_FILE}"

  echo "${USER_PAT_MATRIX}" | jq -r '.[] | "| \(.user) | \(.repos_accessed_with_pat | if length > 3 then (.[0:3] | join(", ")) + " +\(length - 3) more" else join(", ") end) | \(.token_types_used | if length > 0 then join(", ") else "—" end) | \(.audit_event_count // .event_count // 0) | \(.first_activity // "—") | \(.last_activity // "—") |"' >> "${REPORT_FILE}" 2>/dev/null || true
else
  echo "_No per-user PAT activity detected in the audit log._" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << 'SECTION7'

---

## 7. Organization Members

| Login | Name | Role | Account Created |
|-------|------|------|----------------|
SECTION7

echo "${ALL_MEMBERS}" | jq -r '.[] | "| \(.login) | \(.name // "—") | \(.role // "—") | \(.createdAt // "—") |"' >> "${REPORT_FILE}" 2>/dev/null || true

cat >> "${REPORT_FILE}" << 'SECTION8'

---

## 8. Repository Inventory

| Repository | Private | Archived | Last Push |
|-----------|---------|----------|-----------|
SECTION8

echo "${ALL_REPOS}" | jq -r '.[] | "| \(.nameWithOwner) | \(.isPrivate) | \(.isArchived) | \(.pushedAt // "Never") |"' >> "${REPORT_FILE}" 2>/dev/null || true

cat >> "${REPORT_FILE}" << 'FOOTER'

---

## Data Files

The following JSON data files are included in this artifact:

| File | Description |
|------|-------------|
| `repositories.json` | All org repositories with metadata |
| `members.json` | All org members with roles |
| `credential_authorizations.json` | SAML SSO authorized credentials (PATs + SSH keys) |
| `audit_pat_events.json` | Audit log events related to PAT lifecycle |
| `audit_token_access.json` | Audit log events with token-based authentication |
| `actor_summary.json` | Aggregated actor activity summary |
| `workflow_secrets.json` | Workflows using custom secrets (PAT detection) |
| `user_pat_matrix.json` | Per-user PAT activity matrix |

---

*Report generated by [PAT Audit GitHub Action](../.github/workflows/pat-audit.yml)*
FOOTER

echo ""
echo "============================================"
echo "  Report generated: ${REPORT_FILE}"
echo "  Data files in: ${REPORT_DIR}/"
echo "============================================"

# =============================================================================
# SECTION 11: GitHub Actions Job Summary (rendered in the Actions UI)
# =============================================================================
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo ""
  echo ">> Step 11: Writing GitHub Actions Job Summary..."

  SUMMARY="${GITHUB_STEP_SUMMARY}"

  cat >> "${SUMMARY}" << SUMMARY_HEADER
# 🔐 PAT Audit Report — \`${ORG_NAME}\`

| | |
|---|---|
| **Organization** | \`${ORG_NAME}\` |
| **Run Date** | ${TIMESTAMP} |
| **Authenticated As** | \`${AUTH_USER}\` |
| **Lookback Period** | ${LOOKBACK_DAYS} days (since ${LOOKBACK_DATE}) |

---

## 📊 Overview

| Metric | Count |
|:-------|------:|
| Total Repositories | **${REPO_COUNT}** |
| Total Members | **${MEMBER_COUNT}** |
| SAML SSO Authorized PATs | **${PAT_CRED_COUNT}** |
| SAML SSO Authorized SSH Keys | **${SSH_CRED_COUNT}** |
| PAT Lifecycle Audit Events | **${PAT_AUDIT_COUNT}** |
| Token Auth Audit Events | **${TOKEN_AUTH_COUNT}** |
| Unique Actors in Audit Log | **${ACTOR_COUNT}** |
| Workflows Using Custom Secrets | **${WORKFLOW_SECRET_COUNT}** |
| Users with PAT Activity | **${USER_MATRIX_COUNT}** |

---

## 🔑 SAML SSO Authorized Tokens

Tokens authorized for SAML SSO access. Shows the token owner, identifier, scopes granted, and when it was last used.

SUMMARY_HEADER

  if [[ "${PAT_CRED_COUNT}" -gt 0 ]]; then
    echo "| User | Token (last 8) | Scopes | Authorized | Last Accessed | Expires |" >> "${SUMMARY}"
    echo "|:-----|:--------------:|:-------|:-----------|:--------------|:--------|" >> "${SUMMARY}"
    echo "${PAT_CREDS}" | jq -r '.[] | "| `\(.login)` | `\(.token_last_eight)` | \(.scopes | join(", ")) | \(.credential_authorized_at // "—") | \(.credential_accessed_at // "Never") | \(.authorized_credential_expires_at // "Never") |"' >> "${SUMMARY}" 2>/dev/null || true
  else
    cat >> "${SUMMARY}" << 'NO_SAML'
> **No SAML SSO authorized PATs found.**
> This is expected if the organization does not enforce SAML SSO.
> Without SAML, classic PATs cannot be enumerated via API — see the audit log tables below.
NO_SAML
  fi

  cat >> "${SUMMARY}" << 'PAT_EVENTS_HEADER'

---

## 📋 PAT Lifecycle Events

Token creation, approval, denial, and revocation events from the org audit log.

PAT_EVENTS_HEADER

  if [[ "${PAT_AUDIT_COUNT}" -gt 0 ]]; then
    echo "| Date | Event | Actor | Target User | Repository |" >> "${SUMMARY}"
    echo "|:-----|:------|:------|:------------|:-----------|" >> "${SUMMARY}"
    echo "${PAT_AUDIT_EVENTS}" | jq -r '.[0:50] | .[] |
      "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | `\(.action | split(".") | last)` | `\(.actor // "N/A")` | `\(.user // "—")` | \(.repo // "—") |"
    ' >> "${SUMMARY}" 2>/dev/null || true
    if [[ "${PAT_AUDIT_COUNT}" -gt 50 ]]; then
      echo "" >> "${SUMMARY}"
      echo "_Showing 50 of ${PAT_AUDIT_COUNT} events. Download the artifact for the full list._" >> "${SUMMARY}"
    fi
  else
    echo "> _No PAT lifecycle events found in the last ${LOOKBACK_DAYS} days._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'TOKEN_AUTH_HEADER'

---

## 🤖 Token-Authenticated Access

API calls made using a PAT or by a bot/app, showing who used which token type against which repository.

TOKEN_AUTH_HEADER

  if [[ "${TOKEN_AUTH_COUNT}" -gt 0 ]]; then
    echo "| Date | Action | User | Repository | Token Type |" >> "${SUMMARY}"
    echo "|:-----|:-------|:-----|:-----------|:-----------|" >> "${SUMMARY}"
    echo "${TOKEN_AUTH_EVENTS}" | jq -r '.[0:50] | .[] |
      "| \(."@timestamp" // .created_at | if type == "number" then . / 1000 | todate else . end) | `\(.action)` | `\(.actor // "N/A")` | \(.repo // "—") | \(.programmatic_access_type // "classic PAT") |"
    ' >> "${SUMMARY}" 2>/dev/null || true
    if [[ "${TOKEN_AUTH_COUNT}" -gt 50 ]]; then
      echo "" >> "${SUMMARY}"
      echo "_Showing 50 of ${TOKEN_AUTH_COUNT} events. Download the artifact for the full list._" >> "${SUMMARY}"
    fi
  else
    echo "> _No token-authenticated access events found in the last ${LOOKBACK_DAYS} days._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'ACTOR_HEADER'

---

## 👤 Actor Summary

Users and bots observed making API calls, ranked by activity. Highlights programmatic access and bot accounts.

ACTOR_HEADER

  if [[ "${ACTOR_COUNT}" -gt 0 ]]; then
    echo "| User | Total Events | Bot? | Token Access? | First Seen | Last Seen | Repos Accessed |" >> "${SUMMARY}"
    echo "|:-----|-------------:|:----:|:-------------:|:-----------|:----------|---------------:|" >> "${SUMMARY}"
    echo "${ACTOR_SUMMARY}" | jq -r '.[] |
      "| `\(.actor)` | \(.total_events) | \(if .is_bot then "✅" else "—" end) | \(if .has_programmatic_access then "✅" else "—" end) | \(.first_seen) | \(.last_seen) | \(.repos_accessed | length) |"
    ' >> "${SUMMARY}" 2>/dev/null || true
  else
    echo "> _No actors found in audit log for this period._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'MEMBERS_HEADER'

---

## � Workflows Using Custom Secrets (PAT Detection)

Workflow files that reference secrets other than `GITHUB_TOKEN` — these likely use a user-created PAT or custom token.

MEMBERS_HEADER

  if [[ "${WORKFLOW_SECRET_COUNT}" -gt 0 ]]; then
    echo "| Repository | Workflow | Secrets Used |" >> "${SUMMARY}"
    echo "|:-----------|:---------|:-------------|" >> "${SUMMARY}"
    echo "${WORKFLOW_SECRETS}" | jq -r '.[0:50] | .[] |
      "| `\(.repo)` | `\(.workflow | split("/") | last)` | \(.secrets | map("`\(.)`") | join(", ")) |"
    ' >> "${SUMMARY}" 2>/dev/null || true
    if [[ "${WORKFLOW_SECRET_COUNT}" -gt 50 ]]; then
      echo "" >> "${SUMMARY}"
      echo "_Showing 50 of ${WORKFLOW_SECRET_COUNT} workflows. Download the artifact for the full list._" >> "${SUMMARY}"
    fi
  else
    echo "> _No workflows found using custom secrets._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'USER_MATRIX_HEADER'

---

## 🧑‍💻 Per-User PAT Activity

Which repos each user accessed using a PAT, what token types were used, and when they were last active.

USER_MATRIX_HEADER

  if [[ "${USER_MATRIX_COUNT}" -gt 0 ]]; then
    echo "| User | Repos Accessed via PAT | Token Type | Events | Last Active |" >> "${SUMMARY}"
    echo "|:-----|:----------------------|:-----------|-------:|:------------|" >> "${SUMMARY}"
    echo "${USER_PAT_MATRIX}" | jq -r '.[] |
      "| `\(.user)` | \(.repos_accessed_with_pat | if length == 0 then "—" elif length > 3 then (.[0:3] | join(", ")) + " +\(length - 3) more" else join(", ") end) | \(.token_types_used | if length > 0 then join(", ") else "—" end) | \(.audit_event_count // .event_count // 0) | \(.last_activity // "—") |"
    ' >> "${SUMMARY}" 2>/dev/null || true
  else
    echo "> _No per-user PAT activity detected._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'MEMBERS_HEADER2'

---

## 👥 Organization Members

MEMBERS_HEADER2

  echo "| User | Name | Role | Account Created |" >> "${SUMMARY}"
  echo "|:-----|:-----|:-----|:----------------|" >> "${SUMMARY}"
  echo "${ALL_MEMBERS}" | jq -r '.[] |
    "| `\(.login)` | \(.name // "—") | \(.role // "—") | \(.createdAt // "—") |"
  ' >> "${SUMMARY}" 2>/dev/null || true

  cat >> "${SUMMARY}" << 'REPOS_HEADER'

---

## 📦 Repository Inventory

REPOS_HEADER

  echo "| Repository | Visibility | Archived | Last Push |" >> "${SUMMARY}"
  echo "|:-----------|:-----------|:--------:|:----------|" >> "${SUMMARY}"
  echo "${ALL_REPOS}" | jq -r '.[0:100] | .[] |
    "| `\(.nameWithOwner)` | \(if .isPrivate then "🔒 Private" else "🌐 Public" end) | \(if .isArchived then "📁 Yes" else "—" end) | \(.pushedAt // "Never") |"
  ' >> "${SUMMARY}" 2>/dev/null || true

  if [[ "${REPO_COUNT}" -gt 100 ]]; then
    echo "" >> "${SUMMARY}"
    echo "_Showing 100 of ${REPO_COUNT} repositories. Download the artifact for the full list._" >> "${SUMMARY}"
  fi

  cat >> "${SUMMARY}" << 'SUMMARY_FOOTER'

---

> 📎 **Full data available in the workflow artifact** — download the `pat-audit-report` artifact for complete JSON data files and the detailed Markdown report.
SUMMARY_FOOTER

  echo "   Job summary written to GITHUB_STEP_SUMMARY"
fi
echo ""
echo ">> Files produced:"
ls -la "${REPORT_DIR}/"
