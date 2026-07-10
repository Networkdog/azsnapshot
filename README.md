# azsnapshot

Exhaustive **Azure configuration & governance snapshot** in a single Python file with
minimal dependencies. It extracts *everything your identity can read* about how your
Azure estate is **configured and governed** — across the whole tenant plus **Microsoft
Entra ID** — bundles it into **one ZIP**, and uploads it to a Storage Account via a
**container SAS URL**.

It is designed to be the foundation for later tools: virtual-network topology diagrams,
resource-relationship graphs, a resource explorer, configuration diagnostics, or a
Defender-for-Cloud–style CSPM. The snapshot is plain JSON/NDJSON, so anything can consume it.

> **It never reads data.** No storage blob/file/queue/table contents, no database rows,
> no Key Vault secret/key/certificate **values**, no logs, no messages, no cost line items.
> Every call is a **GET**; the tool never invokes `listKeys` / `list-secrets`-style POST
> actions, and secret-bearing fields are redacted before writing.

---

## Quick start

The tool authenticates with `DefaultAzureCredential`, so in most environments you just need
to be signed in (`az login`) — or run it where a managed identity is available.

```bash
# 1) Sign in (skip in Azure Cloud Shell — you're already signed in)
az login

# 2) Run it (one line). Uploads the ZIP to your container SAS URL.
python3 azsnapshot.py --sas-url "https://<acct>.blob.core.windows.net/<container>?<SAS>"
```

Write the ZIP locally without uploading:

```bash
python3 azsnapshot.py --dry-run --out .
```

On a clean machine the tool **auto-installs** its two dependencies (`azure-identity`,
`requests`) on first run. To disable that, pass `--no-auto-install` and install manually:

```bash
python3 -m pip install -r requirements.txt
```

---

## What it collects

**Layer 1 — Azure Resource Graph (KQL), in parallel**
- Tenant hierarchy: management groups, subscriptions, resource groups
- All resources with full properties, SKU, identity, tags, zones, kind
- RBAC: role assignments, role definitions, classic administrators, deny assignments
- Policy: assignments, definitions, initiatives, exemptions
- Microsoft Defender for Cloud: secure scores, assessments, sub-assessments, regulatory
  compliance, Defender plans, alerts
- Advisor recommendations; resource & service health; backup/recovery; guest configuration;
  patch, maintenance, Kubernetes configuration, extended-location resources

**Layer 2 — Exhaustive ARM REST (batched, parallel)**
- A full authoritative **GET on every resource** at its latest API version (captures details
  Resource Graph may normalize or omit)
- **Child sub-resources** not returned inline by the parent (SQL databases/failover/auditing,
  Storage service configs & lifecycle policies, Cosmos databases/containers, App Service
  config/slots/settings, Key Vault object metadata)
- **Diagnostic settings** for every resource
- **Resource locks**, **management-group hierarchy**, **provider registrations**,
  **budgets**, and a **Policy compliance summary**

**Layer 3 — Microsoft Entra ID (Microsoft Graph)**
- Organization, domains, users, groups (+ memberships), service principals, application
  registrations, directory roles, administrative units, OAuth2 permission grants,
  directory role definitions/assignments, **PIM** eligible/active assignments,
  **Conditional Access** policies, and named locations

If a Graph permission is missing, that collector is skipped with a warning (the run continues).

---

## Required access

| Purpose | Least-privilege role |
| --- | --- |
| Resources, config, RBAC, Policy, exhaustive GET | **Reader** at the tenant root management group (or per subscription) |
| Defender for Cloud data | **Security Reader** |
| Microsoft Entra ID (Layer 3) | Microsoft Graph **Directory.Read.All** (plus **Policy.Read.All** and **RoleManagement.Read.Directory** for Conditional Access / PIM) |
| Key Vault object metadata (opt-in, `--include-keyvault-metadata`) | **Key Vault Reader** (data-plane; names/expiry only, never values) |
| Upload destination | A **container SAS** with `Create`, `Write`, `Add` (and `List`) permissions |

---

## Generating a container SAS

Grant only what upload needs, and keep it short-lived:

```bash
# Create the destination container (once)
az storage container create --account-name <acct> --name snapshots --auth-mode login

# Container-scoped SAS, write-only, valid 8 hours
az storage container generate-sas \
  --account-name <acct> --name snapshots \
  --permissions acw --expiry $(date -u -d '8 hours' '+%Y-%m-%dT%H:%MZ') \
  --https-only --auth-mode login --as-user -o tsv
```

Then either pass `--sas-url "https://<acct>.blob.core.windows.net/snapshots?<SAS>"` or set
the environment variable `AZSNAP_SAS_URL` (the SAS is a secret — do not commit or log it).

Prefer RBAC over a SAS? The tool also works unattended with a managed identity that has the
**Storage Blob Data Contributor** role — see the ACI example below (in that case you would
extend the uploader to use the identity; the built-in uploader uses SAS).

---

## Output

A single `azsnapshot-<tenantId>-<UTC timestamp>.zip` containing one `<category>.ndjson`
file per collection plus a `manifest.json`. When uploaded, it lands at
`<container>/<tenantId>/<timestamp>/azsnapshot-...zip` and (unless `--no-latest`) a
`latest.zip` pointer is refreshed.

`manifest.json` records the run id, tenant, subscriptions in scope, options, per-category
record **counts**, and any **warnings/errors** (per-item failures never abort the run).

---

## Azure Cloud Shell & long runs

Cloud Shell has a **~20-minute idle timeout** and then **recycles the container**, so
`nohup`/background jobs do not survive. For large tenants:

1. **Use `--resume` (most reliable).** Output is written to disk immediately as NDJSON, so a
   killed run can be continued. Point it at a stable working directory under the persistent
   `~/clouddrive`:

   ```bash
   python3 azsnapshot.py --sas-url "$AZSNAP_SAS_URL" \
     --work-dir ~/clouddrive/azsnap-work --resume --keep-temp
   ```

   Re-run the exact same command if the session drops — it skips already-collected resource
   details and diagnostics and finishes the rest.

2. **Scope and speed up** so a run fits in the window: `--subscription <id>` (repeatable) or
   `--management-group <id>`, raise `--concurrency`, and disable the heaviest steps with
   `--no-diagnostics` and `--no-group-members`. Use `--resource-detail arg-only` to skip the
   exhaustive Stage 2 entirely for a fast inventory.

3. **Keep the session active** with `tmux` (available in Cloud Shell). The tool also prints a
   heartbeat every ~60s.

4. **For big or recurring snapshots, run it unattended** and skip Cloud Shell altogether —
   see below.

---

## Unattended (Azure Container Instances) with a managed identity

Package the single file and schedule it. A minimal image:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY azsnapshot.py requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "azsnapshot.py"]
```

```bash
# Build & push to your registry, then run with a user-assigned managed identity that has
# Reader (root MG) + Security Reader, and pass the SAS via a secure environment variable.
az container create \
  --resource-group <rg> --name azsnapshot \
  --image <registry>/azsnapshot:latest \
  --assign-identity <userAssignedIdentityResourceId> \
  --restart-policy Never \
  --secure-environment-variables AZSNAP_SAS_URL="https://<acct>.blob.core.windows.net/snapshots?<SAS>" \
  --command-line "python azsnapshot.py --concurrency 24"
```

`DefaultAzureCredential` automatically picks up the container's managed identity — no
interactive login. The same image works in Azure Automation, Container Apps Jobs, or a
scheduled pipeline.

---

## Options

Run `python3 azsnapshot.py --help` for the full list. Frequently used:

| Option | Purpose |
| --- | --- |
| `--sas-url` / `AZSNAP_SAS_URL` | Container SAS URL to upload the ZIP (required unless `--dry-run`) |
| `--dry-run` | Build the ZIP locally, do not upload |
| `--subscription` | Limit to specific subscription IDs (repeatable) |
| `--management-group` | Scope Resource Graph to a management group |
| `--resource-detail full\|arg-only` | Exhaustive Stage 2 (default) vs fast inventory |
| `--concurrency` | Parallel worker threads (default 16) |
| `--batch-size` | ARM/Graph `$batch` size (default 20) |
| `--work-dir` + `--resume` | Stable working dir + continue a prior run |
| `--no-entra` / `--no-group-members` | Skip Entra ID / skip group membership expansion |
| `--no-diagnostics` / `--no-children` | Skip diagnostic settings / child sub-resources |
| `--include-keyvault-metadata` | Add Key Vault object metadata (names/expiry, no values) |
| `--cloud` | `AzureCloud` (default), `AzureUSGovernment`, `AzureChinaCloud` |
| `--no-auto-install` | Do not auto-install dependencies |

---

## Security notes

- No secrets are stored in code; tokens come from `azure-identity`. The SAS is read from an
  argument or environment variable and is never logged.
- The tool is **GET-only** and never lists key/secret material; secret-bearing fields are
  redacted (`[REDACTED]`).
- A snapshot is a complete map of your infrastructure and identity — treat it as sensitive.
  Store it in a **private** storage account (no public blob access), scope the SAS tightly,
  and consider enabling blob versioning/immutability.
