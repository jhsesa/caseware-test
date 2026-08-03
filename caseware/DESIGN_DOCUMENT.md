# Caseware Collaborate — Authorization Layer
## Architecture & Design Document

> **Scope:** This document covers the authorization layer only. The upstream identity provider (Caseware IdP, SAML federation) is treated as an external dependency. User credential storage and MFA are explicitly out of scope per the problem statement.

---

## 1. High-Level Architecture

Collaborate's authorization layer must satisfy three concurrent demands:

| Demand | Scale Target | Key Constraint |
|---|---|---|
| Permission checks | 10,000+ checks/sec | No DB round-trip per request |
| Token revocation | < 2 seconds | Long-lived WebSocket sessions in flight |
| OBO delegation | N service calls/user action | No "Confused Deputy" vulnerability |

### 1a. Identity Routing — Internal vs. Federated Users

```
Client Request
      │
      ▼
Collaborate API GW  ← validates JWT (JwtBearerHandler)
      │  Which IdP?
 ─────┴─────
│           │
Caseware    Per-firm OIDC/SAML
Central IdP Federation (dynamic scheme per tenant)
│           │
└─────┬─────┘
      │  Normalized OIDC token with tenant_id
      ▼
  Token Store
```

Per-firm federation uses named authentication schemes registered dynamically from a `FirmConfiguration` table. ASP.NET Core's `IAuthenticationSchemeProvider` supports runtime scheme registration without restart.

### 1b. Permission Authorization — L1/L2 Epoch Cache

```
Incoming JWT (perm_epoch=42)
         │
         ▼
CachedPermissionEpochStore [L1 — IMemoryCache, 2s TTL]
    HIT  ──► compare epoch → 200 OK
    MISS ─┐
          ▼
RedisPermissionEpochStore [L2 — Redis Cluster, 24h TTL]
    Key: perm_epoch:{userId}
    = 42  ──► compare epoch → 200 OK
    = nil ──► 403 Forbidden (revoked / not seeded)

Permission Revoked Event:
  DB write → event bus → consumer:
    RevokeAsync(userId) → DEL L2 key + evict L1
    Other instances see revocation within ≤ 2s (L1 TTL)
```

**Epoch pattern vs denylist:** An epoch check is always O(1) — one Redis GET per user. A token denylist is O(n) and grows unboundedly with token volume.

### 1c. On-Behalf-Of Flow — RFC 8693 Token Exchange

```
Reporting Service  →  POST /oauth/v2/token
                       subject_token: <user JWT>
                       actor_token:   <service JWT>
                       scope: financial:read
                    ↓
                    1. Validate subject_token (JwtSecurityTokenHandler)
                    2. Validate actor_token
                    3. Check actor allowlist
                    4. Enforce scope ⊆ subject scopes
                    5. Issue downstream JWT:
                         sub  = original user      ← immutable
                         act  = {sub: svc:reporting} ← deputy
                         scope= financial:read      ← narrowed
                    ↓
Reporting Service  →  GET /workspaces/ws-42/financial-data
                       Authorization: Bearer <downstream JWT>
                    ↓
                    OboDelegationHandler validates:
                      act claim present ✓
                      scope financial:read ✓
                      perm_epoch matches Redis ✓
                    ↓
                    { subject: user-7f3a, delegated_by: {sub: svc:reporting} }
```

The `act` claim is a **nested JSON object** (RFC 8693 §4.1). Both `sub` (user) and `act.sub` (service) are logged on every access — complete forensic auditability of who requested data AND which service executed it.

---

## 2. Implementation Plan

### What is implemented in this submission

| Component | Status | Notes |
|---|---|---|
| `POST /oauth/v2/token` (RFC 8693) | ✅ Complete | Full protocol validation + actor allowlist |
| `GET /workspaces/{id}/financial-data` | ✅ Complete | `RequireOboDelegation` policy enforced |
| L1 IMemoryCache decorator | ✅ Complete | `CachedPermissionEpochStore`, 2-second TTL |
| L2 Redis epoch store | ✅ Complete | `RedisPermissionEpochStore` via StackExchange.Redis |
| Integration tests (Testcontainers) | ✅ Complete | Real Redis; revocation, scope, Confused Deputy |
| OpenAPI spec (`/openapi/v1.json`) | ✅ Complete | Available in development |

### What is explicitly out of scope (with rationale)

| Component | Why deferred |
|---|---|
| PKCE / Auth Code login flow | "Implementing the full identity provider is outside scope" (test statement) |
| Dynamic per-firm OIDC/SAML scheme registration | Requires DB-backed `FirmConfiguration`; assumed as external dependency |
| Workspace-level role DB queries | `IFinancialDataService` is stubbed; pattern is demonstrated through policy |
| WebSocket session eviction on revocation | Event bus consumer pattern documented; not wired in this slice |

### Why both A and C (not just one)

The test asks for one slice — depth over breadth. C (token exchange) *produces* the downstream JWT that A (resource endpoint) *consumes*. Demonstrating A without C means showing a protected endpoint that can never receive a valid token. The two form a single coherent end-to-end flow, not two separate slices.

### Production rollout phases

**Phase 1 (this submission):** Token Exchange, OBO policy, epoch-based revocation with L1/L2 cache.

**Phase 2:** Dynamic OIDC/SAML scheme registration. PKCE with per-firm `client_id` isolation.

**Phase 3:** Replace stubbed `IFinancialDataService` with DB-backed permission queries. Add workspace-role and resource-override claim hydration at exchange time — evaluated once, cached in the downstream JWT.

**Phase 4:** WebSocket eviction via SignalR hub groups keyed by `userId`. Event bus consumer calls `IHubContext.Groups.RemoveFromGroupAsync` on `perm.revoked`.

---

## 3. Testing Strategy

```
         ▲
        /E2E\          Postman / k6 against staging
       /──────\
      / Integ. \       WebApplicationFactory + Testcontainers Redis  ← IMPLEMENTED
     /──────────\
    / Unit Tests \     OboDelegationHandler, TokenExchangeService isolation
   ──────────────
```

**Implemented integration scenarios:**

| Test | Proves |
|---|---|
| `WhenPermissionsRevoked_SubsequentRequest_Returns403` | Epoch revocation works end-to-end with real Redis |
| `WhenActClaimMissing_Request_Returns403` | Confused Deputy protection cannot be bypassed by stripping `act` |
| `WhenScopeInsufficient_Request_Returns403` | Scope narrowing enforced at the resource |

**Infrastructure decisions:**
- `CollaborateWebFactory` (`IAsyncLifetime`) starts Redis once per class — no per-test Docker overhead.
- `ConfigureTestServices` replaces only `IPermissionEpochStore`. All other middleware (JWT validation, policy registration, serializer) runs unmodified from `Program.cs`, maximizing production fidelity.

---

## 4. Evaluation & Observability

### Structured Logging (in place)

Every rejection logs a structured event with the relevant claims, ready for CloudWatch Logs Insights:

```
[WARN] OBO policy: perm_epoch mismatch. jwt=42 stored=null sub=user-7f3a act=svc:reporting
[WARN] Delegation denied. Actor 'unknown-svc' not in allowlist.
[INFO] Token exchange issued. sub=user-7f3a act=reporting-service scope=[financial:read]
[ERROR] Epoch store unavailable. Failing closed. sub=user-7f3a
```

### Key Metrics

| Metric | Dimensions | Alert |
|---|---|---|
| `token_exchange.issued` | `actor_client_id`, `audience` | — |
| `token_exchange.rejected` | `error_code` | > 10/min |
| `authorization.check.p99_ms` | `policy_name`, `result` | > 50 ms |
| `epoch_store.l1_hit_ratio` | `instance_id` | < 0.90 |
| `epoch_store.l2_error_rate` | — | > 0 |
| `permission.revocation.latency_ms` | `tenant_id` | p99 > 2,000 ms |

### Distributed Tracing

`builder.Services.AddOpenTelemetry()` with `AddAspNetCoreInstrumentation()` and `AddRedisInstrumentation()`. Every token exchange and authorization check is a traceable span, correlatable by `trace_id` across the gateway, token service, and downstream APIs. Deploy to **AWS X-Ray** via the OpenTelemetry SDK.

### AWS Stack

| Concern | Service |
|---|---|
| Metrics + alerting | CloudWatch Metrics + Alarms |
| Log aggregation | CloudWatch Logs Insights |
| Distributed tracing | AWS X-Ray (OpenTelemetry) |
| Redis L2 | ElastiCache for Redis (cluster mode, Multi-AZ) |
| Signing keys | AWS Secrets Manager + automatic rotation |

---

## 5. Failure Modes & Tradeoffs

| Failure | Impact | Mitigation |
|---|---|---|
| **Redis outage** | 403 on all protected endpoints after L1 TTL expires | Polly circuit breaker on `IConnectionMultiplexer`; return `503 Retry-After`, not 500 |
| **L1 stampede** | Many concurrent requests miss L1 simultaneously | L1 is per-user key; concurrent reads for same user are independent reads — no write-on-miss contention |
| **Stale revocation (≤ 2s)** | Other instances may serve 200 for up to 2s post-revocation | Acceptable per ADR; WebSocket eviction closes the session gap |
| **Malformed revocation event** | Wrong user locked out | Idempotent `SetEpochAsync` restores access; ops tooling can call directly |
| **Actor allowlist misconfiguration** | Legitimate service rejected | Config-driven (`AllowedActorClientIds`); hot-reload without restart |
| **`sub` claim absent from IdP** | `IssueDownstreamToken` → `invalid_grant` | Guard at `TokenExchangeService:192` returns clean error |
| **Clock skew > 30s** | Token rejected as expired/future | `ClockSkew = 30s` in `TokenValidationParameters`; NTP enforced at infrastructure level |
| **HS256 key compromise** | All tokens valid with compromised key | **Production MUST use RS256** with AWS Secrets Manager rotation — all code comments flag this explicitly |

### The Core Tradeoff

The epoch pattern trades **strict immediate revocation** (impossible without synchronous DB calls on every request) for **bounded eventual revocation** (≤ 2s). This is the correct tradeoff at 10,000+ RPS: a DB query per request would require ~200× more DB capacity and add 5–20 ms of latency on every authorization check.
