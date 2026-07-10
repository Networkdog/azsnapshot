#!/usr/bin/env python3
"""
azsnapshot - Azure configuration & governance snapshot (single-file, minimal deps).

Exhaustively extracts CONFIGURATION and GOVERNANCE metadata reachable by the signed-in
identity across the tenant plus Microsoft Entra ID, in parallel, then bundles everything
into a single ZIP and (optionally) uploads it to a Storage Account via a container SAS URL.

It NEVER reads data-plane DATA (storage blob/file/queue/table contents, database rows,
Key Vault secret/key/certificate VALUES, logs, messages, cost line items). It performs
GET-only calls and never invokes listKeys / list-secrets style POST actions. Secret-bearing
fields are redacted.

Typical one-liner (local or Azure Cloud Shell - az is already logged in there):

    python3 azsnapshot.py --sas-url "https://acct.blob.core.windows.net/container?<SAS>"

Dry run (write ZIP locally, no upload):

    python3 azsnapshot.py --dry-run --out .

See README.md for required roles, SAS generation, Cloud Shell tips and unattended (ACI) usage.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

VERSION = "1.0.0"

# --------------------------------------------------------------------------------------
# Cloud endpoints
# --------------------------------------------------------------------------------------
CLOUDS = {
    "AzureCloud": {
        "arm": "https://management.azure.com",
        "graph": "https://graph.microsoft.com",
        "kv_suffix": "vault.azure.net",
        "arm_scope": "https://management.azure.com/.default",
        "graph_scope": "https://graph.microsoft.com/.default",
        "kv_scope": "https://vault.azure.net/.default",
    },
    "AzureUSGovernment": {
        "arm": "https://management.usgovcloudapi.net",
        "graph": "https://graph.microsoft.us",
        "kv_suffix": "vault.usgovcloudapi.net",
        "arm_scope": "https://management.usgovcloudapi.net/.default",
        "graph_scope": "https://graph.microsoft.us/.default",
        "kv_scope": "https://vault.usgovcloudapi.net/.default",
    },
    "AzureChinaCloud": {
        "arm": "https://management.chinacloudapi.cn",
        "graph": "https://microsoftgraph.chinacloudapi.cn",
        "kv_suffix": "vault.azure.cn",
        "arm_scope": "https://management.chinacloudapi.cn/.default",
        "graph_scope": "https://microsoftgraph.chinacloudapi.cn/.default",
        "kv_scope": "https://vault.azure.cn/.default",
    },
}

# API versions
ARG_API = "2024-04-01"
ARM_BATCH_API = "2020-06-01"
SUBS_API = "2022-12-01"
PROVIDERS_API = "2021-04-01"
LOCKS_API = "2020-05-01"
MG_API = "2020-05-01"
DIAG_API = "2021-05-01-preview"
BUDGETS_API = "2021-10-01"
POLICYSTATES_API = "2019-10-01"
KV_DATAPLANE_API = "7.4"
BLOB_API_VERSION = "2021-08-06"
GRAPH_VERSION = "v1.0"

# Tuning defaults
DEFAULT_CONCURRENCY = 16
DEFAULT_BATCH_SIZE = 20
DEFAULT_ARG_CONCURRENCY = 4
LARGE_TENANT_WARN = 100000
HEARTBEAT_SECONDS = 60
HTTP_TIMEOUT = 120
MAX_HTTP_ATTEMPTS = 6
BLOB_BLOCK_SIZE = 32 * 1024 * 1024        # 32 MiB blocks for staged upload
BLOB_SINGLE_PUT_MAX = 128 * 1024 * 1024   # single Put Blob threshold

# --------------------------------------------------------------------------------------
# Azure Resource Graph KQL catalog (embedded; override with --queries-dir).
# Each entry becomes one <category>.ndjson file. Non-existent tables are skipped gracefully.
# Verified against the Microsoft Learn "Supported tables" reference. Governance tables are
# queried WHOLE (not filtered by subtype) so nothing is missed; downstream filters by `type`.
# --------------------------------------------------------------------------------------
KQL_CATALOG = {
    # Hierarchy + all resources ('resources' is special: also builds the Stage-2 worklist).
    "resourcecontainers": "resourcecontainers",
    "resources": "resources",
    # Governance / identity / policy / security (whole tables = every subtype captured:
    # role assignments/definitions/classic admins/deny assignments; policy assignments/
    # definitions/set definitions/exemptions/metadata/enrollments/versions; Defender posture).
    "authorizationresources": "authorizationresources",
    "policyresources": ("policyresources | where type !in~ "
                        "('microsoft.policyinsights/policystates',"
                        "'microsoft.policyinsights/componentpolicystates')"),
    "securityresources": "securityresources",
    # Recommendations / health
    "advisorresources": "advisorresources",
    "healthresources": "healthresources",
    "servicehealthresources": "servicehealthresources",
    # Backup / business continuity
    "recoveryservicesresources": "recoveryservicesresources",
    "azurebusinesscontinuityresources": "azurebusinesscontinuityresources",
    # Configuration / management add-ons and governance
    "guestconfigurationresources": "guestconfigurationresources",
    "patchassessmentresources": "patchassessmentresources",
    "maintenanceresources": "maintenanceresources",
    "kubernetesconfigurationresources": "kubernetesconfigurationresources",
    "extendedlocationresources": "extendedlocationresources",
    "featureresources": "featureresources",                 # preview feature registrations
    "capabilityresources": "capabilityresources",
    "deploymentresources": "deploymentresources",           # deployment stacks
    # Networking (extended) + DNS record sets
    "networkresources": "networkresources",
    "dnsresources": "dnsresources",
    # Compute / platform inventory (instance-level & specialized)
    "computeresources": "computeresources",                 # VMSS instance VMs + NICs
    "communitygalleryresources": "communitygalleryresources",
    "aksresources": "aksresources",                         # AKS fleets
    "servicefabricresources": "servicefabricresources",
    "appserviceresources": "appserviceresources",           # site/slot config
    "batchresources": "batchresources",
    "kustoresources": "kustoresources",
    "elasticsanresources": "elasticsanresources",
    "desktopvirtualizationresources": "desktopvirtualizationresources",
    # Specialized / other providers
    "chaosresources": "chaosresources",
    "iotsecurityresources": "iotsecurityresources",
    "edgeorderresources": "edgeorderresources",
    "impactreportresources": "impactreportresources",
    "azuredevopsplatformresources": "azuredevopsplatformresources",
    "awsresources": "awsresources",                         # multicloud connector inventory
    # Intentionally excluded:
    #  - change-history/event streams (microsoft.resources/changes): resourcechanges,
    #    resourcecontainerchanges, healthresourcechanges, networkresourcechanges,
    #    maintenanceresourcechanges, quotaresourcechanges, extensibilityresourcechanges
    #  - patchinstallationresources (patch-run events)
    #  - alertsmanagementresources (fired alert instances)
    #  - policyinsights policystates / componentpolicystates (per-resource compliance
    #    evaluation, potentially millions of rows; summarized via the Policy compliance REST call)
    # Also omitted: tables listed in the docs that ARG does not expose as directly queryable
    # (they return HTTP 400) - tagresources (tags are already on every 'resources' row),
    # insightresources, managedserviceresources, orbitalresources, sportresources, mirgateresources.
    # Add any table via --queries-dir if your tenant supports it.
}


# --------------------------------------------------------------------------------------
# Child sub-resource registry for exhaustive extraction (children NOT inline in parent GET).
# Keyed by lowercase resource type -> list of (relative_path, needs_value_redaction).
# The base GET already returns inline children (subnets, NSG rules, peerings, agent pools...),
# so this only covers separately-addressed collections/objects.
# Extend freely; the default handler (base GET) covers everything else.
# --------------------------------------------------------------------------------------
CHILD_REGISTRY = {
    "microsoft.sql/servers": [
        ("databases", False), ("elasticPools", False), ("firewallRules", False),
        ("virtualNetworkRules", False), ("failoverGroups", False), ("administrators", False),
        ("auditingSettings", False), ("securityAlertPolicies", False),
        ("encryptionProtector", False), ("vulnerabilityAssessments", False),
    ],
    "microsoft.storage/storageaccounts": [
        ("blobServices/default", False), ("fileServices/default", False),
        ("queueServices/default", False), ("tableServices/default", False),
        ("managementPolicies/default", False), ("encryptionScopes", False),
        ("privateEndpointConnections", False), ("objectReplicationPolicies", False),
    ],
    "microsoft.documentdb/databaseaccounts": [
        ("sqlDatabases", False), ("mongodbDatabases", False), ("gremlinDatabases", False),
        ("cassandraKeyspaces", False), ("tables", False),
    ],
    "microsoft.web/sites": [
        ("config/web", False), ("config/appsettings", True), ("config/connectionstrings", True),
        ("config/authsettingsV2", False), ("slots", False), ("hostNameBindings", False),
        ("virtualNetworkConnections", False), ("functions", False),
    ],
    "microsoft.keyvault/vaults": [
        ("keys", False), ("secrets", False),  # management-plane metadata only (no values)
    ],
}

# --------------------------------------------------------------------------------------
# Microsoft Graph (Entra ID) collectors: (category, path, params, required_permission_hint)
# Each is a paged list. A 403 is recorded as a warning and skipped.
# --------------------------------------------------------------------------------------
GRAPH_USER_SELECT = (
    "id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,"
    "onPremisesSyncEnabled,department,jobTitle,companyName,usageLocation"
)
GRAPH_GROUP_SELECT = (
    "id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,visibility,"
    "membershipRule,membershipRuleProcessingState,isAssignableToRole,createdDateTime"
)
GRAPH_COLLECTORS = [
    ("entra_organization", "organization", {}),
    ("entra_domains", "domains", {}),
    ("entra_users", "users", {"$select": GRAPH_USER_SELECT}),
    ("entra_groups", "groups", {"$select": GRAPH_GROUP_SELECT}),
    ("entra_service_principals", "servicePrincipals", {}),
    ("entra_applications", "applications", {}),
    ("entra_directory_roles", "directoryRoles", {}),
    ("entra_administrative_units", "directory/administrativeUnits", {}),
    ("entra_oauth2_permission_grants", "oauth2PermissionGrants", {}),
    ("entra_role_definitions", "roleManagement/directory/roleDefinitions", {}),
    ("entra_role_assignments", "roleManagement/directory/roleAssignments", {}),
    ("entra_pim_eligible", "roleManagement/directory/roleEligibilityScheduleInstances", {}),
    ("entra_pim_active", "roleManagement/directory/roleAssignmentScheduleInstances", {}),
    ("entra_conditional_access", "identity/conditionalAccess/policies", {}),
    ("entra_named_locations", "identity/conditionalAccess/namedLocations", {}),
]

# --------------------------------------------------------------------------------------
# Redaction: key-name based, applied to every record before writing.
# --------------------------------------------------------------------------------------
REDACT_EXACT = {
    "password", "adminpassword", "administratorloginpassword", "protectedsettings",
    "clientsecret", "certificatepassword", "sshprivatekey", "privatekey",
}
REDACT_SUBSTR = [
    "password", "secret", "connectionstring", "primarykey", "secondarykey",
    "accountkey", "accesskey", "sharedkey", "saskey", "sastoken", "authkey",
    "apikey", "storagekey", "credentials", "x-functions-key",
]
REDACTED = "[REDACTED]"

# --------------------------------------------------------------------------------------
# Globals populated after dependency bootstrap.
# --------------------------------------------------------------------------------------
requests = None  # type: ignore  # set by _late_imports()
_QUIET = False


def log(msg: str) -> None:
    if not _QUIET:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        sys.stderr.write(f"[{ts}] {msg}\n")
        sys.stderr.flush()


# --------------------------------------------------------------------------------------
# Dependency bootstrap (keeps the tool a true one-liner on a fresh machine / Cloud Shell)
# --------------------------------------------------------------------------------------
def _ensure_deps(auto_install: bool) -> None:
    missing = []
    try:
        import azure.identity  # noqa: F401
    except Exception:
        missing.append("azure-identity>=1.16.0")
    try:
        import requests  # noqa: F401
    except Exception:
        missing.append("requests>=2.28.0")
    if not missing:
        return
    if not auto_install:
        sys.stderr.write(
            "Missing dependencies: %s\nInstall them, e.g.:\n    %s -m pip install %s\n"
            % (", ".join(missing), sys.executable, " ".join(missing))
        )
        sys.exit(2)
    log("Installing missing dependencies: %s" % ", ".join(missing))
    base = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    # In a venv install straight into it; on a system/Cloud Shell interpreter prefer --user,
    # then fall back to --break-system-packages (PEP 668 externally-managed environments).
    variants = ([[], ["--break-system-packages"]] if in_venv
                else [["--user"], ["--break-system-packages"], ["--user", "--break-system-packages"], []])
    last_err = ""
    for extra in variants:
        try:
            subprocess.run(base + extra + missing, check=True, capture_output=True, text=True)
            break
        except subprocess.CalledProcessError as exc:
            last_err = (exc.stderr or exc.stdout or "").strip()
        except Exception as exc:  # pragma: no cover - pip missing entirely, etc.
            last_err = str(exc)
    else:
        sys.stderr.write(
            "Automatic install failed for %s. Install manually:\n    %s -m pip install %s\n%s\n"
            % (", ".join(missing), sys.executable, " ".join(missing), last_err[-500:])
        )
        sys.exit(2)
    # Make freshly installed packages importable in this already-running process.
    import importlib
    import site
    try:
        site.main()  # re-evaluate site dirs
    except Exception:
        pass
    user_site = site.getusersitepackages() if hasattr(site, "getusersitepackages") else None
    if user_site and user_site not in sys.path and os.path.isdir(user_site):
        sys.path.append(user_site)
    importlib.invalidate_caches()


def _late_imports() -> None:
    global requests
    import requests as _rq  # type: ignore
    requests = _rq


# --------------------------------------------------------------------------------------
# HTTP infrastructure
# --------------------------------------------------------------------------------------
class HttpError(Exception):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} for {url}: {body[:400]}")
        self.status = status
        self.url = url
        self.body = body


class RateLimiter:
    """Optional per-host minimum-interval limiter. Disabled when rps <= 0."""

    def __init__(self, rps: float):
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.min_interval
        if sleep_for:
            time.sleep(sleep_for)


class TokenProvider:
    """Thread-safe multi-scope token cache backed by an azure-identity credential."""

    def __init__(self, credential, scopes: dict):
        self._cred = credential
        self._scopes = scopes  # kind -> scope string
        self._lock = threading.Lock()
        self._cache: dict = {}  # kind -> (token, expires_on)

    def token(self, kind: str) -> str:
        scope = self._scopes[kind]
        with self._lock:
            entry = self._cache.get(kind)
            now = time.time()
            if entry and entry[1] - now > 300:
                return entry[0]
            access = self._cred.get_token(scope)
            self._cache[kind] = (access.token, access.expires_on)
            return access.token

    def invalidate(self, kind: str) -> None:
        with self._lock:
            self._cache.pop(kind, None)


class HttpClient:
    def __init__(self, tokens: TokenProvider, concurrency: int, max_rps: float = 0.0):
        self.tokens = tokens
        self.session = requests.Session()
        pool = max(concurrency * 2, 10)
        adapter = requests.adapters.HTTPAdapter(pool_connections=pool, pool_maxsize=pool, max_retries=0)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._limiter = RateLimiter(max_rps)

    def request(self, method: str, url: str, kind: str, *, json_body=None, params=None,
                headers=None, allow=(), timeout=HTTP_TIMEOUT):
        attempt = 0
        while True:
            attempt += 1
            self._limiter.wait()
            hdrs = {"Authorization": "Bearer " + self.tokens.token(kind),
                    "Accept": "application/json"}
            if json_body is not None:
                hdrs["Content-Type"] = "application/json"
            if headers:
                hdrs.update(headers)
            try:
                resp = self.session.request(method, url, params=params, json=json_body,
                                            headers=hdrs, timeout=timeout)
            except requests.RequestException as exc:  # transient network error
                if attempt >= MAX_HTTP_ATTEMPTS:
                    raise HttpError(0, url, f"network error: {exc}")
                time.sleep(min(2 ** attempt, 30) + 0.1 * attempt)
                continue

            sc = resp.status_code
            if sc == 401 and attempt == 1:
                self.tokens.invalidate(kind)
                continue
            if sc in (429, 500, 502, 503, 504) and sc not in allow:
                if attempt >= MAX_HTTP_ATTEMPTS:
                    raise HttpError(sc, url, resp.text)
                delay = self._retry_after(resp)
                if delay is None:
                    delay = min(2 ** attempt, 45) + 0.25 * attempt
                time.sleep(delay)
                continue
            if sc >= 400 and sc not in allow:
                raise HttpError(sc, url, resp.text)
            return resp

    @staticmethod
    def _retry_after(resp) -> float | None:
        val = resp.headers.get("Retry-After")
        if not val:
            return None
        try:
            return float(val)
        except ValueError:
            return None


# --------------------------------------------------------------------------------------
# Output writer: thread-safe NDJSON, one file per category, append-friendly for --resume.
# --------------------------------------------------------------------------------------
class SnapshotWriter:
    def __init__(self, workdir: str, append_categories=frozenset()):
        self.workdir = workdir
        self._append = set(append_categories)
        self._files: dict = {}
        self._locks: dict = {}
        self._create_lock = threading.Lock()

    def _handle(self, category: str):
        f = self._files.get(category)
        if f is not None:
            return f, self._locks[category]
        with self._create_lock:
            f = self._files.get(category)
            if f is None:
                mode = "a" if category in self._append else "w"
                path = os.path.join(self.workdir, category + ".ndjson")
                f = open(path, mode, encoding="utf-8")
                self._files[category] = f
                self._locks[category] = threading.Lock()
            return self._files[category], self._locks[category]

    def write(self, category: str, obj) -> None:
        line = json.dumps(redact(obj), ensure_ascii=False, default=str)
        f, lock = self._handle(category)
        with lock:
            f.write(line)
            f.write("\n")

    def write_many(self, category: str, objs) -> int:
        objs = list(objs)
        if not objs:
            return 0
        lines = "".join(json.dumps(redact(o), ensure_ascii=False, default=str) + "\n" for o in objs)
        f, lock = self._handle(category)
        with lock:
            f.write(lines)
        return len(objs)

    def flush(self, category: str) -> None:
        f = self._files.get(category)
        if f is not None:
            with self._locks[category]:
                f.flush()

    def close(self) -> None:
        for f in self._files.values():
            try:
                f.close()
            except Exception:
                pass


def redact(obj):
    """Recursively replace secret-bearing field values with a placeholder."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in REDACT_EXACT or any(s in kl for s in REDACT_SUBSTR):
                out[k] = REDACTED if v is not None else None
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def chunked(iterable, size):
    it = iter(iterable)
    while True:
        block = list(itertools.islice(it, size))
        if not block:
            return
        yield block


# --------------------------------------------------------------------------------------
# The snapshotter
# --------------------------------------------------------------------------------------
class Snapshotter:
    def __init__(self, args, cloud, tokens: TokenProvider, http: HttpClient, writer: SnapshotWriter):
        self.args = args
        self.cloud = cloud
        self.tokens = tokens
        self.http = http
        self.writer = writer
        self.arm = cloud["arm"]
        self.graph = f"{cloud['graph']}/{GRAPH_VERSION}"
        self.executor = futures.ThreadPoolExecutor(max_workers=args.concurrency)
        self.errors: list = []
        self.warnings: list = []
        self._err_lock = threading.Lock()
        self.tenant_id = None
        self.subscriptions: list = []
        self.api_versions: dict = {}
        self._counter = itertools.count(1)
        self._arg_sem = threading.BoundedSemaphore(max(1, args.arg_concurrency))
        self.resource_count = 0
        self._done_ids = set()      # for --resume (Stage 2 resource detail)
        self._done_diag = set()     # for --resume (diagnostics)
        self._hb_stop = threading.Event()
        self._progress = {"resource_detail": 0, "resource_total": 0}

    # -- error/warn helpers -------------------------------------------------------------
    def error(self, stage: str, target: str, message: str) -> None:
        with self._err_lock:
            self.errors.append({"stage": stage, "target": target, "message": str(message)[:500]})
        log(f"ERROR [{stage}] {target}: {str(message)[:200]}")

    def warn(self, stage: str, target: str, message: str) -> None:
        with self._err_lock:
            self.warnings.append({"stage": stage, "target": target, "message": str(message)[:500]})
        log(f"WARN  [{stage}] {target}: {str(message)[:200]}")

    # -- generic ARM helpers ------------------------------------------------------------
    def arm_url(self, path: str, api: str) -> str:
        sep = "&" if "?" in path else "?"
        return f"{self.arm}{path}{sep}api-version={api}"

    def arm_get(self, path: str, api: str, allow=(404,)):
        url = path if path.startswith("http") else self.arm_url(path, api)
        resp = self.http.request("GET", url, "arm", allow=allow)
        if resp.status_code in allow and resp.status_code >= 400:
            return None
        return resp.json() if resp.content else None

    def arm_get_all(self, path: str, api: str):
        """GET a list endpoint following nextLink; returns list of items."""
        out = []
        url = self.arm_url(path, api)
        while url:
            resp = self.http.request("GET", url, "arm")
            data = resp.json() if resp.content else {}
            if isinstance(data, dict) and "value" in data:
                out.extend(data["value"])
                url = data.get("nextLink")
            else:
                if data:
                    out.append(data)
                url = None
        return out

    # -- discovery ----------------------------------------------------------------------
    def discover(self) -> None:
        subs = self.arm_get_all("/subscriptions", SUBS_API)
        wanted = set(self.args.subscription or [])
        selected = []
        for s in subs:
            sid = s.get("subscriptionId")
            if wanted and sid not in wanted:
                continue
            if s.get("state") and s["state"] not in ("Enabled", "Warned", "PastDue"):
                continue
            selected.append(s)
            if not self.tenant_id:
                self.tenant_id = s.get("tenantId")
        self.subscriptions = selected
        if not self.tenant_id:
            self.tenant_id = _jwt_claim(self.tokens.token("arm"), "tid") or "unknown-tenant"
        log(f"Tenant {self.tenant_id}: {len(self.subscriptions)} subscription(s) in scope")

    def sub_ids(self):
        return [s["subscriptionId"] for s in self.subscriptions]

    # -- Azure Resource Graph -----------------------------------------------------------
    def arg_query(self, query: str, label=None):
        """Yield rows for a KQL query, honoring ARG's hard limits.

        ARG limits handled here:
          * <=1000 rows per page ($top) -> follow $skipToken until absent for the full set.
          * 30s per-query timeout + subscription-count limits -> the in-scope subscriptions are
            queried in chunks of --arg-sub-chunk (scope partitioning, as the docs recommend),
            so no single query spans too many subscriptions.
          * resultTruncated without $skipToken (unpageable query shape) -> warn.
        A shared semaphore bounds concurrent ARG requests to protect the per-tenant quota.
        """
        if self.args.management_group:
            yield from self._arg_paged(query, {"managementGroups": [self.args.management_group]}, label)
            return
        sub_ids = self.sub_ids()
        if not sub_ids:
            yield from self._arg_paged(query, {}, label)  # tenant scope
            return
        chunk = self.args.arg_sub_chunk if self.args.arg_sub_chunk > 0 else len(sub_ids)
        for i in range(0, len(sub_ids), chunk):
            yield from self._arg_paged(query, {"subscriptions": sub_ids[i:i + chunk]}, label)

    def _arg_paged(self, query, scope, label):
        """Run one ARG query for a given scope, paging via $skipToken until exhausted."""
        url = f"{self.arm}/providers/Microsoft.ResourceGraph/resources?api-version={ARG_API}"
        skip_token = None
        while True:
            body = {"query": query, "options": {"resultFormat": "objectArray", "$top": 1000}}
            body.update(scope)
            if skip_token:
                body["options"]["$skipToken"] = skip_token
            with self._arg_sem:
                resp = self.http.request("POST", url, "arm", json_body=body)
            self._respect_arg_quota(resp)
            data = resp.json()
            for row in data.get("data", []):
                yield row
            skip_token = data.get("$skipToken")
            if not skip_token:
                if str(data.get("resultTruncated", "")).lower() == "true":
                    self.warn("arg", label or "query",
                              "resultTruncated: results may be incomplete - scope the run with "
                              "--subscription or --management-group")
                break

    @staticmethod
    def _respect_arg_quota(resp) -> None:
        try:
            remaining = int(resp.headers.get("x-ms-user-quota-remaining", "100"))
        except ValueError:
            remaining = 100
        if remaining <= 2:
            resets = resp.headers.get("x-ms-user-quota-resets-after", "00:00:05")
            secs = _parse_hms(resets)
            log(f"ARG quota low; sleeping {secs}s")
            time.sleep(min(secs + 1, 30))

    def collect_arg_table(self, category: str, query: str) -> None:
        try:
            count = 0
            batch = []
            for row in self.arg_query(query, label=category):
                batch.append(row)
                if len(batch) >= 500:
                    count += self.writer.write_many(category, batch)
                    batch = []
            count += self.writer.write_many(category, batch)
            log(f"ARG {category}: {count}")
        except HttpError as exc:
            # Table may not exist in this tenant, or access denied - record and move on.
            self.warn("arg", category, exc)
        except Exception as exc:
            self.error("arg", category, exc)

    def collect_resources(self):
        """Stream the 'resources' table to disk and write a compact on-disk worklist
        (_worklist.tsv) for Stage 2. Nothing is held in memory, so this scales to
        hundreds of thousands / millions of resources."""
        count = 0
        batch = []
        wl_path = os.path.join(self.writer.workdir, "_worklist.tsv")
        try:
            with open(wl_path, "w", encoding="utf-8") as wl:
                for row in self.arg_query("resources", label="resources"):
                    rid = row.get("id")
                    if rid:
                        rtype = (row.get("type") or "").lower()
                        name = (row.get("name") or "").replace("\t", " ").replace("\n", " ")
                        loc = (row.get("location") or "").replace("\t", " ").replace("\n", " ")
                        wl.write(f"{rid}\t{rtype}\t{name}\t{loc}\n")
                    batch.append(row)
                    if len(batch) >= 500:
                        count += self.writer.write_many("resources", batch)
                        batch = []
                count += self.writer.write_many("resources", batch)
        except Exception as exc:
            self.error("arg", "resources", exc)
        self.resource_count = count
        log(f"ARG resources: {count}")

    def _iter_worklist(self):
        """Yield (id, type, name, location) tuples streamed from _worklist.tsv."""
        path = os.path.join(self.writer.workdir, "_worklist.tsv")
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 4:
                    parts += [""] * (4 - len(parts))
                yield parts[0], parts[1], parts[2], parts[3]

    # -- providers + API version discovery ---------------------------------------------
    def collect_providers_and_versions(self) -> None:
        def fetch(sub_id):
            try:
                items = self.arm_get_all(f"/subscriptions/{sub_id}/providers", PROVIDERS_API)
            except Exception as exc:
                self.warn("providers", sub_id, exc)
                return []
            self.writer.write_many("resource_providers",
                                   [{"subscriptionId": sub_id, **p} for p in items])
            return items

        merged = {}
        for providers in self._map(fetch, self.sub_ids(), stage="providers"):
            for prov in providers or []:
                ns = (prov.get("namespace") or "").lower()
                for rt in prov.get("resourceTypes", []):
                    key = f"{ns}/{(rt.get('resourceType') or '').lower()}"
                    if key in merged:
                        continue
                    merged[key] = rt.get("defaultApiVersion") or _best_api_version(rt.get("apiVersions") or [])
        self.api_versions = merged
        log(f"Providers + API versions: {len(merged)} resource types")

    def api_version_for(self, rtype: str) -> str:
        return self.api_versions.get(rtype.lower()) or "2021-04-01"

    # -- Stage 2: exhaustive per-resource detail via ARM $batch -------------------------
    def collect_resource_details(self) -> None:
        total = self.resource_count
        self._progress["resource_total"] = total
        self._progress["resource_detail"] = len(self._done_ids)
        if total >= LARGE_TENANT_WARN:
            log(f"NOTE: {total} resources - Stage 2 (full per-resource GET) is very large. "
                f"Consider --resource-detail arg-only, --subscription/--management-group scoping, "
                f"or --max-resource-detail.")
        log(f"Stage 2: resource detail for up to {total} resource(s)"
            + (f" ({len(self._done_ids)} already done)" if self._done_ids else ""))
        cap = self.args.max_resource_detail

        def gen():
            n = 0
            for rid, rtype, _n, _l in self._iter_worklist():
                if rid in self._done_ids:
                    continue
                yield (rid, rtype)
                n += 1
                if cap and n >= cap:
                    self.warn("resource_detail", "cap",
                              f"--max-resource-detail {cap} reached; remaining resources skipped")
                    return

        def do_batch(items):
            reqs = []
            idmap = {}
            for i, (rid, rtype) in enumerate(items):
                key = str(i)
                idmap[key] = (rid, rtype)
                url = f"{self.arm}{rid}?api-version={self.api_version_for(rtype)}"
                reqs.append({"httpMethod": "GET", "name": key, "url": url})
            try:
                responses = self._arm_batch(reqs)
            except Exception as exc:
                for rid, _ in items:
                    self.error("resource_detail", rid, exc)
                return
            out = []
            for key, (status, content) in responses.items():
                rid, rtype = idmap[key]
                if 200 <= status < 300:
                    out.append({"id": rid, "type": rtype, "apiVersion": self.api_version_for(rtype),
                                "status": status, "resource": content})
                else:
                    out.append({"id": rid, "type": rtype, "status": status,
                                "error": _short_error(content)})
            self.writer.write_many("resource_detail", out)
            self._progress["resource_detail"] += len(items)

        self._stream_chunks(gen(), self.args.batch_size, do_batch, stage="resource_detail")

        if not self.args.no_children:
            self.collect_children()

    def collect_children(self) -> None:
        def gen():
            for rid, rtype, _n, _l in self._iter_worklist():
                paths = CHILD_REGISTRY.get(rtype)
                if paths:
                    yield (rid, rtype, paths)

        def do_chunk(entries):
            for rid, rtype, paths in entries:
                api = self.api_version_for(rtype)
                for rel, redact_values in paths:
                    full = f"{rid}/{rel}"
                    try:
                        data = self.arm_get(full, api, allow=(400, 403, 404, 405, 409, 501))
                    except HttpError as exc:
                        if exc.status not in (400, 403, 404, 405, 409, 501):
                            self.warn("children", full, exc)
                        continue
                    except Exception as exc:
                        self.warn("children", full, exc)
                        continue
                    if data is None:
                        continue
                    items = data.get("value") if isinstance(data, dict) and "value" in data else [data]
                    for item in items:
                        if redact_values:
                            item = _blank_setting_values(item)
                        self.writer.write("resource_children",
                                          {"parentId": rid, "childType": rel, "child": item})

        log("Stage 2: enumerating child sub-resources")
        self._stream_chunks(gen(), 8, do_chunk, stage="children")

    # -- Stage 2: diagnostic settings ---------------------------------------------------
    def collect_diagnostics(self) -> None:
        log("Stage 2: diagnostic settings")

        def gen():
            for rid, rtype, _n, _l in self._iter_worklist():
                if rid in self._done_diag:
                    continue
                yield (rid, rtype)

        def do_batch(items):
            reqs = []
            idmap = {}
            for i, (rid, _rtype) in enumerate(items):
                key = str(i)
                idmap[key] = rid
                url = f"{self.arm}{rid}/providers/microsoft.insights/diagnosticSettings?api-version={DIAG_API}"
                reqs.append({"httpMethod": "GET", "name": key, "url": url})
            try:
                responses = self._arm_batch(reqs)
            except Exception as exc:
                for rid, _ in items:
                    self.warn("diagnostics", rid, exc)
                return
            out = []
            for key, (status, content) in responses.items():
                rid = idmap[key]
                if 200 <= status < 300 and isinstance(content, dict):
                    settings = content.get("value") or []
                    if settings:
                        out.append({"id": rid, "diagnosticSettings": settings})
            if out:
                self.writer.write_many("diagnostic_settings", out)

        self._stream_chunks(gen(), self.args.batch_size, do_batch, stage="diagnostics")

    # -- ARM $batch --------------------------------------------------------------------
    def _arm_batch(self, reqs):
        """Submit an ARM $batch of GETs; returns {name: (status, content)} with item retry."""
        url = f"{self.arm}/batch?api-version={ARM_BATCH_API}"
        result = {}
        pending = list(reqs)
        attempt = 0
        while pending:
            attempt += 1
            resp = self.http.request("POST", url, "arm", json_body={"requests": pending})
            data = resp.json() if resp.content else {}
            retry = []
            for item in data.get("responses", []):
                name = item.get("name")
                status = item.get("httpStatusCode", 0)
                if status == 429 and attempt < MAX_HTTP_ATTEMPTS:
                    retry.append(next(r for r in pending if r["name"] == name))
                    continue
                result[name] = (status, item.get("content"))
            pending = retry
            if pending:
                time.sleep(min(2 ** attempt, 30))
        return result

    # -- governance via REST ------------------------------------------------------------
    def collect_governance(self) -> None:
        # Each sub-collector is internally parallel (via _map) and is driven from this
        # (non-worker) thread, so there is no nested executor submission / deadlock.
        self.collect_subscription_details()
        self.collect_locks()
        self.collect_management_groups()
        self.collect_budgets()
        self.collect_policy_compliance()

    def collect_locks(self) -> None:
        def one(sub_id):
            try:
                items = self.arm_get_all(
                    f"/subscriptions/{sub_id}/providers/Microsoft.Authorization/locks", LOCKS_API)
                return self.writer.write_many("resource_locks", items)
            except Exception as exc:
                self.warn("locks", sub_id, exc)
                return 0
        self._map(one, self.sub_ids(), stage="locks")

    def collect_management_groups(self) -> None:
        try:
            groups = self.arm_get_all("/providers/Microsoft.Management/managementGroups", MG_API)
        except HttpError as exc:
            self.warn("mgmt_groups", "list", exc)
            return
        self.writer.write_many("management_groups", groups)
        # Expand hierarchy for each group (children + settings).
        def expand(g):
            gid = g.get("name")
            try:
                path = (f"/providers/Microsoft.Management/managementGroups/{gid}"
                        "?$expand=children&$recurse=true")
                detail = self.arm_get(path, MG_API, allow=(403, 404))
                if detail:
                    self.writer.write("management_group_hierarchy", detail)
            except Exception as exc:
                self.warn("mgmt_groups", str(gid), exc)
        self._map(expand, groups, stage="mgmt_groups")

    def collect_subscription_details(self) -> None:
        # Provider registrations are captured by collect_providers_and_versions().
        for s in self.subscriptions:
            self.writer.write("subscription_details", s)

    def collect_budgets(self) -> None:
        if self.args.no_budgets:
            return
        def one(sub_id):
            try:
                items = self.arm_get_all(
                    f"/subscriptions/{sub_id}/providers/Microsoft.Consumption/budgets", BUDGETS_API)
                self.writer.write_many("budgets", [{"subscriptionId": sub_id, **b} for b in items])
            except Exception as exc:
                self.warn("budgets", sub_id, exc)
        self._map(one, self.sub_ids(), stage="budgets")

    def collect_policy_compliance(self) -> None:
        if self.args.no_policy_compliance:
            return
        def one(sub_id):
            url = (f"{self.arm}/subscriptions/{sub_id}/providers/Microsoft.PolicyInsights"
                   f"/policyStates/latest/summarize?api-version={POLICYSTATES_API}")
            try:
                resp = self.http.request("POST", url, "arm", allow=(403, 404))
                if resp.status_code >= 400:
                    return
                data = resp.json()
                for item in data.get("value", []):
                    self.writer.write("policy_compliance_summary", {"subscriptionId": sub_id, **item})
            except Exception as exc:
                self.warn("policy_compliance", sub_id, exc)
        self._map(one, self.sub_ids(), stage="policy_compliance")

    # -- Key Vault object metadata (opt-in, data-plane LIST, no values) -----------------
    def collect_keyvault_metadata(self) -> None:
        vaults = [(rid, name) for (rid, rtype, name, _l) in self._iter_worklist()
                  if rtype == "microsoft.keyvault/vaults" and name]
        if not vaults:
            return
        log(f"Key Vault metadata: {len(vaults)} vault(s)")
        suffix = self.cloud["kv_suffix"]

        def one(entry):
            rid, name = entry
            base = f"https://{name}.{suffix}"
            for kind in ("secrets", "keys", "certificates"):
                url = f"{base}/{kind}?api-version={KV_DATAPLANE_API}"
                try:
                    while url:
                        resp = self.http.request("GET", url, "kv", allow=(403, 404))
                        if resp.status_code >= 400:
                            break
                        data = resp.json()
                        for item in data.get("value", []):
                            self.writer.write("keyvault_objects",
                                              {"vaultId": rid, "objectKind": kind, "object": item})
                        url = data.get("nextLink")
                except Exception as exc:
                    self.warn("keyvault", f"{name}/{kind}", exc)
        self._map(one, vaults, stage="keyvault")

    # -- Microsoft Entra ID via Graph ---------------------------------------------------
    def collect_entra(self) -> None:
        if not self.args.include_entra:
            return
        log("Entra ID: collecting directory objects")
        self._map(self._entra_one, GRAPH_COLLECTORS, stage="entra")
        if not self.args.no_group_members:
            self.collect_group_members()

    def _entra_one(self, spec):
        category, path, params = spec
        try:
            count = self._graph_write(category, path, params)
            log(f"Graph {category}: {count}")
        except HttpError as exc:
            if exc.status in (403, 401):
                self.warn("entra", category, f"insufficient Graph permission ({exc.status})")
            else:
                self.error("entra", category, exc)
        except Exception as exc:
            self.error("entra", category, exc)

    def _graph_write(self, category, path, params) -> int:
        url = f"{self.graph}/{path}"
        count = 0
        first = True
        while url:
            resp = self.http.request("GET", url, "graph",
                                     params=params if first else None,
                                     headers={"ConsistencyLevel": "eventual"})
            first = False
            data = resp.json() if resp.content else {}
            values = data.get("value")
            if values is None:
                self.writer.write(category, data)
                count += 1
            else:
                count += self.writer.write_many(category, values)
            url = data.get("@odata.nextLink")
        return count

    def collect_group_members(self) -> None:
        self.writer.flush("entra_groups")  # ensure prior writes are on disk before re-reading
        group_ids = _read_ids(os.path.join(self.writer.workdir, "entra_groups.ndjson"))
        if not group_ids:
            return
        log(f"Entra ID: members/owners for {len(group_ids)} group(s)")

        def do_batch(ids):
            reqs = []
            idmap = {}
            for i, gid in enumerate(ids):
                idmap[str(i)] = gid
                reqs.append({"id": str(i), "method": "GET",
                             "url": f"/groups/{gid}/members?$select=id,displayName&$top=999"})
            try:
                responses = self._graph_batch(reqs)
            except Exception as exc:
                self.warn("entra", "group_members", exc)
                return
            out = []
            for rid, (status, body) in responses.items():
                gid = idmap[rid]
                if status == 200 and isinstance(body, dict):
                    members = [m.get("id") for m in body.get("value", [])]
                    out.append({"groupId": gid, "members": members})
            if out:
                self.writer.write_many("entra_group_members", out)

        self._for_each_chunk(group_ids, 20, do_batch, stage="group_members")

    def _graph_batch(self, reqs):
        url = f"{self.graph}/$batch"
        result = {}
        pending = list(reqs)
        attempt = 0
        while pending:
            attempt += 1
            resp = self.http.request("POST", url, "graph", json_body={"requests": pending})
            data = resp.json() if resp.content else {}
            retry = []
            for item in data.get("responses", []):
                rid = item.get("id")
                status = item.get("status", 0)
                if status == 429 and attempt < MAX_HTTP_ATTEMPTS:
                    retry.append(next(r for r in pending if r["id"] == rid))
                    continue
                result[rid] = (status, item.get("body"))
            pending = retry
            if pending:
                time.sleep(min(2 ** attempt, 30))
        return result

    # -- parallel helpers ---------------------------------------------------------------
    def _map(self, fn, items, stage: str):
        items = list(items)
        if not items:
            return []
        results = []
        future_map = {self.executor.submit(fn, it): it for it in items}
        for fut in futures.as_completed(future_map):
            try:
                results.append(fut.result())
            except Exception as exc:
                self.error(stage, str(future_map[fut])[:120], exc)
        return results

    def _for_each_chunk(self, items, size, fn, stage: str):
        chunks = list(chunked(items, size))
        if not chunks:
            return
        future_map = {self.executor.submit(fn, c): i for i, c in enumerate(chunks)}
        for fut in futures.as_completed(future_map):
            try:
                fut.result()
            except Exception as exc:
                self.error(stage, f"chunk-{future_map[fut]}", exc)

    def _stream_chunks(self, item_iter, size, fn, stage: str, max_inflight=None):
        """Chunk a (possibly huge) iterator and run fn(chunk) in parallel with a bounded
        number of in-flight futures, so memory stays flat regardless of total size."""
        if max_inflight is None:
            max_inflight = max(2, self.args.concurrency * 2)
        inflight = set()

        def drain(target):
            while len(inflight) > target:
                done, _ = futures.wait(inflight, return_when=futures.FIRST_COMPLETED)
                for fut in done:
                    inflight.discard(fut)
                    try:
                        fut.result()
                    except Exception as exc:
                        self.error(stage, "chunk", exc)

        chunk = []
        for item in item_iter:
            chunk.append(item)
            if len(chunk) >= size:
                inflight.add(self.executor.submit(fn, chunk))
                chunk = []
                if len(inflight) >= max_inflight:
                    drain(max_inflight - 1)
        if chunk:
            inflight.add(self.executor.submit(fn, chunk))
        drain(0)

    # -- heartbeat ----------------------------------------------------------------------
    def _heartbeat(self, started):
        while not self._hb_stop.wait(HEARTBEAT_SECONDS):
            elapsed = int(time.time() - started)
            done = self._progress["resource_detail"]
            total = self._progress["resource_total"]
            extra = f" | resource detail {done}/{total}" if total else ""
            log(f"...working ({elapsed}s elapsed){extra}")

    # -- resume support -----------------------------------------------------------------
    def load_resume_state(self):
        self._done_ids = _read_ids(os.path.join(self.writer.workdir, "resource_detail.ndjson"))
        self._done_diag = _read_ids(os.path.join(self.writer.workdir, "diagnostic_settings.ndjson"))
        if self._done_ids or self._done_diag:
            log(f"Resume: {len(self._done_ids)} resource details and "
                f"{len(self._done_diag)} diagnostics already present")

    # -- orchestration ------------------------------------------------------------------
    def run(self):
        started = time.time()
        hb = threading.Thread(target=self._heartbeat, args=(started,), daemon=True)
        hb.start()
        try:
            self.discover()
            if self.args.resume:
                self.load_resume_state()

            # Stage 1: discovery. The large 'resources' ARG scan and the Graph/Entra
            # collection each run on their own thread. None of those threads is a pool
            # worker, so the shared executor is only ever driven from non-worker threads,
            # which avoids nested submission / deadlock even at --concurrency 1.
            log("Stage 1: discovery (ARG + governance%s) in parallel"
                % (" + Entra" if self.args.include_entra else ""))

            def _resources():
                try:
                    self.collect_resources()
                except Exception as exc:
                    self.error("arg", "resources", exc)

            res_thread = threading.Thread(target=_resources, daemon=True)
            res_thread.start()
            entra_thread = None
            if self.args.include_entra:
                def _entra():
                    try:
                        self.collect_entra()
                    except Exception as exc:
                        self.error("entra", "-", exc)

                entra_thread = threading.Thread(target=_entra, daemon=True)
                entra_thread.start()

            self.collect_providers_and_versions()
            self._collect_arg_tables()
            self.collect_governance()

            res_thread.join()
            if entra_thread:
                entra_thread.join()
            log(f"Stage 1 complete: {self.resource_count} resources discovered")

            # Stage 2: exhaustive per-resource detail (+ children, diagnostics, KV metadata).
            # Everything streams from the on-disk worklist, so memory stays flat even at
            # hundreds of thousands / millions of resources.
            if self.args.resource_detail == "full" and self.resource_count:
                self.collect_resource_details()
                if not self.args.no_diagnostics:
                    self.collect_diagnostics()
                if self.args.include_keyvault_metadata:
                    self.collect_keyvault_metadata()
            else:
                log("Stage 2 skipped (resource-detail=arg-only)"
                    if self.resource_count else "Stage 2: no resources")
        except Exception as exc:
            # Never lose a partial snapshot to an unexpected error - record and still finalize.
            self.error("run", "-", exc)
        finally:
            self._hb_stop.set()
            self.writer.close()
            self.executor.shutdown(wait=True)
        return self.finalize(started)

    def _collect_arg_tables(self):
        specs = [(cat, q) for cat, q in KQL_CATALOG.items() if cat != "resources"]
        self._map(lambda s: self.collect_arg_table(s[0], s[1]), specs, stage="arg")

    # -- finalize: manifest, zip, upload ------------------------------------------------
    def finalize(self, started):
        run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        counts = _count_lines(self.writer.workdir)
        manifest = {
            "tool": "azsnapshot",
            "version": VERSION,
            "runId": str(uuid.uuid4()),
            "startedUtc": datetime.fromtimestamp(started, timezone.utc).isoformat(),
            "finishedUtc": datetime.now(timezone.utc).isoformat(),
            "durationSeconds": round(time.time() - started, 1),
            "tenantId": self.tenant_id,
            "cloud": self.args.cloud,
            "subscriptions": [
                {"subscriptionId": s.get("subscriptionId"), "displayName": s.get("displayName"),
                 "state": s.get("state")} for s in self.subscriptions],
            "managementGroupScope": self.args.management_group,
            "options": {
                "resourceDetail": self.args.resource_detail,
                "entra": self.args.include_entra,
                "groupMembers": not self.args.no_group_members,
                "diagnostics": not self.args.no_diagnostics,
                "children": not self.args.no_children,
                "keyVaultMetadata": self.args.include_keyvault_metadata,
                "concurrency": self.args.concurrency,
                "batchSize": self.args.batch_size,
                "argConcurrency": self.args.arg_concurrency,
                "argSubChunk": self.args.arg_sub_chunk,
                "maxResourceDetail": self.args.max_resource_detail or None,
                "resumed": bool(self.args.resume),
            },
            "counts": counts,
            "warnings": self.warnings,
            "errors": self.errors,
        }
        with open(os.path.join(self.writer.workdir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2, default=str)

        zip_name = f"azsnapshot-{self.tenant_id}-{run_ts}.zip"
        zip_path = os.path.join(self.args.out, zip_name)
        _make_zip(self.writer.workdir, zip_path)
        size_mb = os.path.getsize(zip_path) / (1024 * 1024)
        log(f"Wrote {zip_path} ({size_mb:.1f} MiB)")

        blob_url = None
        if not self.args.dry_run and self.args.sas_url:
            blob_url = self.upload_zip(zip_path, zip_name)
        return manifest, zip_path, blob_url

    # -- SAS block-blob upload (no azure-storage-blob dependency) ------------------------
    def upload_zip(self, zip_path, zip_name):
        base, query = _split_sas(self.args.sas_url, self.args.container)
        prefix = f"{self.tenant_id}/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        blob_path = f"{prefix}/{zip_name}"
        target = self._upload_blob(base, query, blob_path, zip_path)
        log(f"Uploaded snapshot to {target.split('?')[0]}")
        if not self.args.no_latest:
            latest = self._upload_blob(base, query, "latest.zip", zip_path)
            log(f"Updated latest pointer at {latest.split('?')[0]}")
        return target.split("?")[0]

    def _upload_blob(self, base, query, blob_path, file_path):
        blob_url = f"{base}/{blob_path}"
        full = f"{blob_url}?{query}"
        size = os.path.getsize(file_path)
        common = {"x-ms-version": BLOB_API_VERSION, "x-ms-blob-content-type": "application/zip"}
        if size <= BLOB_SINGLE_PUT_MAX:
            with open(file_path, "rb") as fh:
                body = fh.read()
            headers = dict(common)
            headers["x-ms-blob-type"] = "BlockBlob"
            resp = self.http.session.put(full, data=body, headers=headers, timeout=HTTP_TIMEOUT * 3)
            if resp.status_code not in (201, 200):
                raise HttpError(resp.status_code, blob_url, resp.text)
            return full
        # Staged block upload for large ZIPs.
        block_ids = []
        with open(file_path, "rb") as fh:
            index = 0
            while True:
                chunk = fh.read(BLOB_BLOCK_SIZE)
                if not chunk:
                    break
                block_id = base64.b64encode(f"{index:08d}".encode()).decode()
                block_ids.append(block_id)
                put = f"{blob_url}?comp=block&blockid={_qs(block_id)}&{query}"
                r = self._retry_put(put, chunk, {"x-ms-version": BLOB_API_VERSION})
                if r.status_code not in (201, 200):
                    raise HttpError(r.status_code, blob_url, r.text)
                index += 1
        body = "<?xml version='1.0' encoding='utf-8'?><BlockList>" + \
               "".join(f"<Latest>{b}</Latest>" for b in block_ids) + "</BlockList>"
        commit = f"{blob_url}?comp=blocklist&{query}"
        headers = dict(common)
        headers["Content-Type"] = "application/xml"
        r = self._retry_put(commit, body.encode("utf-8"), headers)
        if r.status_code not in (201, 200):
            raise HttpError(r.status_code, blob_url, r.text)
        return full

    def _retry_put(self, url, data, headers):
        attempt = 0
        while True:
            attempt += 1
            try:
                r = self.http.session.put(url, data=data, headers=headers, timeout=HTTP_TIMEOUT * 3)
            except requests.RequestException as exc:
                if attempt >= 5:
                    raise HttpError(0, url, f"network error: {exc}")
                time.sleep(min(2 ** attempt, 20))
                continue
            if r.status_code in (429, 500, 502, 503) and attempt < 5:
                time.sleep(min(2 ** attempt, 20))
                continue
            return r


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------
def _jwt_claim(token: str, claim: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get(claim)
    except Exception:
        return None


def _parse_hms(text: str) -> float:
    try:
        parts = [float(p) for p in text.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0.0)
        h, m, s = parts[-3], parts[-2], parts[-1]
        return h * 3600 + m * 60 + s
    except Exception:
        return 5.0


def _best_api_version(versions):
    if not versions:
        return None
    stable = [v for v in versions if "preview" not in v.lower()]
    return sorted(stable or versions, reverse=True)[0]


def _short_error(content):
    if isinstance(content, dict):
        err = content.get("error", content)
        if isinstance(err, dict):
            return {"code": err.get("code"), "message": str(err.get("message", ""))[:300]}
    return {"message": str(content)[:300]}


def _blank_setting_values(item):
    """Redact values in App Service appsettings/connectionstrings-style objects (keep names)."""
    if not isinstance(item, dict):
        return item
    props = item.get("properties")
    if isinstance(props, dict):
        item = dict(item)
        item["properties"] = {k: REDACTED for k in props}
    return item


def _read_ids(path):
    ids = set()
    if not os.path.exists(path):
        return ids
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                val = obj.get("id") or obj.get("groupId")
                if val:
                    ids.add(val)
    except Exception:
        pass
    return ids


def _count_lines(workdir):
    counts = {}
    for name in sorted(os.listdir(workdir)):
        if not name.endswith(".ndjson"):
            continue
        path = os.path.join(workdir, name)
        n = 0
        with open(path, "r", encoding="utf-8") as f:
            for _ in f:
                n += 1
        counts[name[:-len(".ndjson")]] = n
    return counts


def _make_zip(workdir, zip_path):
    os.makedirs(os.path.dirname(os.path.abspath(zip_path)), exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for name in sorted(os.listdir(workdir)):
            if name.startswith("_"):  # internal scratch files (e.g., _worklist.tsv)
                continue
            full = os.path.join(workdir, name)
            if os.path.isfile(full):
                zf.write(full, arcname=name)


def _split_sas(sas_url, container):
    """Return (base_without_query, query_string). If container given, treat sas_url as account."""
    parts = urlsplit(sas_url)
    query = parts.query
    path = parts.path.rstrip("/")
    if container:
        path = f"{path}/{container.strip('/')}"
    base = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return base, query


def _qs(value):
    from urllib.parse import quote
    return quote(value, safe="")


def _blob_error_detail(resp) -> str:
    """Extract a readable reason from an Azure Storage error response."""
    text = (resp.text or "").strip()
    code = re.search(r"<Code>(.*?)</Code>", text)
    msg = re.search(r"<Message>(.*?)</Message>", text)
    detail = (msg.group(1).splitlines()[0] if msg else text[:200])
    out = f"{code.group(1)}: {detail}" if code else detail
    return out.strip(": ") or (resp.reason or f"HTTP {resp.status_code}")


def _preflight_upload(http, args):
    """Prove the destination SAS is writable BEFORE any extraction work by writing and
    deleting a tiny probe blob. Returns (ok, detail). Delete is best-effort (the run itself
    never deletes), so a missing Delete permission does not fail the check."""
    try:
        base, query = _split_sas(args.sas_url, args.container)
    except Exception as exc:
        return False, f"invalid --sas-url ({exc})"
    url = f"{base}/.azsnapshot-preflight/{uuid.uuid4().hex}.txt?{query}"
    headers = {"x-ms-version": BLOB_API_VERSION, "x-ms-blob-type": "BlockBlob",
               "x-ms-blob-content-type": "text/plain"}
    try:
        r = http.session.put(url, data=b"azsnapshot preflight probe", headers=headers, timeout=60)
    except requests.RequestException as exc:
        return False, f"cannot reach the storage endpoint ({exc})"
    if r.status_code not in (200, 201):
        return False, _blob_error_detail(r)
    try:
        http.session.delete(url, headers={"x-ms-version": BLOB_API_VERSION}, timeout=60)
    except Exception:
        pass  # Delete may not be granted; the tiny probe blob is harmless
    return True, "ok"


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="azsnapshot",
        description="Exhaustive Azure configuration & governance snapshot to a ZIP (uploaded via SAS).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--sas-url", default=os.environ.get("AZSNAP_SAS_URL"),
                   help="Container SAS URL to upload the ZIP to (or set AZSNAP_SAS_URL). "
                        "Required unless --dry-run.")
    p.add_argument("--container", default=None,
                   help="Container name to append when --sas-url is an account-level SAS.")
    p.add_argument("--out", default=".", help="Local directory to write the ZIP into.")
    p.add_argument("--work-dir", default=None,
                   help="Stable working directory for intermediate NDJSON (enables --resume). "
                        "Defaults to a subfolder of --out.")
    p.add_argument("--dry-run", action="store_true", help="Do not upload; keep the ZIP locally.")
    p.add_argument("--resume", action="store_true",
                   help="Reuse --work-dir and skip already-collected resource details/diagnostics.")
    p.add_argument("--subscription", action="append",
                   help="Limit to specific subscription ID(s). Repeatable.")
    p.add_argument("--management-group", default=None,
                   help="Scope ARG queries to a management group ID instead of subscriptions.")
    p.add_argument("--resource-detail", choices=["full", "arg-only"], default="full",
                   help="'full' = exhaustive per-resource GET (Stage 2); 'arg-only' = skip Stage 2.")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                   help="Parallel worker threads.")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                   help="ARM/Graph $batch size for Stage 2 fan-out.")
    p.add_argument("--arg-concurrency", type=int, default=DEFAULT_ARG_CONCURRENCY,
                   help="Max concurrent Azure Resource Graph requests (protects the ARG quota).")
    p.add_argument("--arg-sub-chunk", type=int, default=500,
                   help="Max subscriptions per Resource Graph query; partitions the scope to avoid "
                        "the 30s query timeout / subscription-count limits (0 = all in one query).")
    p.add_argument("--max-resource-detail", type=int, default=0,
                   help="Cap Stage 2 per-resource GETs (0 = unlimited); useful for very large tenants.")
    p.add_argument("--max-rps", type=float, default=0.0,
                   help="Optional client-side requests/sec cap (0 = disabled).")
    p.add_argument("--cloud", choices=list(CLOUDS.keys()), default="AzureCloud",
                   help="Azure cloud environment.")
    p.add_argument("--tenant", default=None, help="Tenant ID hint for authentication.")
    p.add_argument("--include-entra", action="store_true",
                   help="Also collect Microsoft Entra ID (Graph) directory objects (off by default).")
    p.add_argument("--no-group-members", action="store_true",
                   help="With --include-entra, skip group membership expansion (the heaviest Graph step).")
    p.add_argument("--no-diagnostics", action="store_true",
                   help="Skip per-resource diagnostic settings.")
    p.add_argument("--no-children", action="store_true",
                   help="Skip child sub-resource enumeration (SQL/Storage/Web/Cosmos/KeyVault).")
    p.add_argument("--no-budgets", action="store_true", help="Skip consumption budgets.")
    p.add_argument("--no-policy-compliance", action="store_true",
                   help="Skip Policy compliance summary.")
    p.add_argument("--include-keyvault-metadata", action="store_true",
                   help="Also list Key Vault object metadata (names/expiry, NO values; "
                        "needs 'Key Vault Reader' data-plane access).")
    p.add_argument("--no-latest", action="store_true", help="Do not upload a latest.zip pointer.")
    p.add_argument("--keep-temp", action="store_true", help="Keep the working directory after run.")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Do not auto-install missing Python dependencies.")
    p.add_argument("--quiet", action="store_true", help="Suppress progress logging.")
    p.add_argument("--version", action="version", version=f"azsnapshot {VERSION}")
    return p.parse_args(argv)


def build_credential(args):
    from azure.identity import DefaultAzureCredential
    kwargs = {"exclude_interactive_browser_credential": True}
    if args.tenant:
        # Constrain interactive/CLI credentials to the requested tenant where supported.
        kwargs["interactive_browser_tenant_id"] = args.tenant
        kwargs["shared_cache_tenant_id"] = args.tenant
        kwargs["visual_studio_code_tenant_id"] = args.tenant
    try:
        return DefaultAzureCredential(**kwargs)
    except TypeError:
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def main(argv=None):
    global _QUIET
    args = parse_args(argv if argv is not None else sys.argv[1:])
    _QUIET = args.quiet

    if not args.dry_run and not args.sas_url:
        sys.stderr.write("error: --sas-url is required unless --dry-run is set "
                         "(or provide AZSNAP_SAS_URL).\n")
        return 2

    _ensure_deps(not args.no_auto_install)
    _late_imports()

    cloud = CLOUDS[args.cloud]
    scopes = {"arm": cloud["arm_scope"], "graph": cloud["graph_scope"], "kv": cloud["kv_scope"]}

    log(f"azsnapshot {VERSION} starting (cloud={args.cloud}, concurrency={args.concurrency})")
    credential = build_credential(args)
    tokens = TokenProvider(credential, scopes)
    try:
        tokens.token("arm")  # fail fast on auth problems
    except Exception as exc:
        sys.stderr.write(f"error: authentication failed: {exc}\n"
                         "Run 'az login' (or use a managed identity) and try again.\n")
        return 3

    http = HttpClient(tokens, args.concurrency, args.max_rps)

    # Preflight: verify the destination is writable BEFORE any extraction work, so a long run
    # never completes only to fail at upload. Writes then deletes a tiny probe blob.
    if not args.dry_run and args.sas_url:
        ok, detail = _preflight_upload(http, args)
        if not ok:
            sys.stderr.write(
                f"error: storage upload preflight failed: {detail}\n"
                "The destination isn't writable - check the SAS URL is correct, not expired, and "
                "grants Create/Write/Add on the container (or use --dry-run to skip upload).\n")
            return 4
        log("Preflight: storage upload verified")

    # Working directory (stable when --work-dir/--resume, else temp).
    os.makedirs(args.out, exist_ok=True)
    if args.work_dir:
        workdir = args.work_dir
    elif args.resume:
        workdir = os.path.join(args.out, ".azsnapshot-work")
    else:
        workdir = tempfile.mkdtemp(prefix="azsnapshot-")
    os.makedirs(workdir, exist_ok=True)
    if not args.resume:
        _clear_dir(workdir)

    # On resume, only the expensive Stage 2 outputs are appended (and de-duplicated by id);
    # Stage 1 tables are rewritten fresh to avoid duplication.
    resumable = frozenset({"resource_detail", "diagnostic_settings"}) if args.resume else frozenset()
    writer = SnapshotWriter(workdir, append_categories=resumable)
    snap = Snapshotter(args, cloud, tokens, http, writer)

    manifest, zip_path, blob_url = snap.run()

    # Summary
    total = sum(manifest["counts"].values())
    log(f"Done in {manifest['durationSeconds']}s: {total} records across "
        f"{len(manifest['counts'])} categories, "
        f"{len(manifest['warnings'])} warnings, {len(manifest['errors'])} errors")
    print(json.dumps({
        "zip": os.path.abspath(zip_path),
        "blob": blob_url,
        "records": total,
        "categories": manifest["counts"],
        "warnings": len(manifest["warnings"]),
        "errors": len(manifest["errors"]),
    }, ensure_ascii=False, indent=2))

    if not args.keep_temp and not args.work_dir and not args.resume:
        _clear_dir(workdir, remove_root=True)
    return 0  # per-item errors are recorded in the manifest; the run itself succeeded


def _clear_dir(path, remove_root=False):
    if not os.path.isdir(path):
        return
    for name in os.listdir(path):
        full = os.path.join(path, name)
        try:
            if os.path.isfile(full):
                os.remove(full)
        except Exception:
            pass
    if remove_root:
        try:
            os.rmdir(path)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
