# Caseware Collaborate — Authorization Layer

Senior Developer Take-Home Submission

---

## Overview

This repository implements a targeted slice of the OAuth2/OIDC authorization layer for **Caseware Collaborate** — a multi-tenant SaaS platform for real-time audit collaboration across firm boundaries.

The implementation demonstrates two complementary scenarios from the problem statement:

| Scenario | Endpoint | RFC |
|---|---|---|
| **C** — On-Behalf-Of token narrowing | `POST /oauth/v2/token` | RFC 8693 Token Exchange |
| **A** — Resource endpoint with policy enforcement | `GET /api/v1/workspaces/{id}/financial-data` | — |

> **Why both A and C?** C produces the token that A consumes — they form one coherent, end-to-end flow demonstrating the full Confused Deputy solution. Neither can be meaningfully demonstrated in isolation.

---

## Architecture

See **[DESIGN_DOCUMENT.md](./DESIGN_DOCUMENT.md)** for the full architecture, implementation plan, observability strategy, and failure mode analysis.

Key design decision: the authorization layer uses an **L1 (IMemoryCache, 2 s TTL) / L2 (Redis) epoch-based revocation** strategy. Permission changes publish an event; the epoch store is updated; any in-flight JWT carrying the old `perm_epoch` is rejected within 2 seconds — without re-issuing tokens or forcing re-authentication.

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| .NET SDK | 8.0+ | Build and run the API |
| Docker | 24.0+ | Required for integration tests (Testcontainers spins up Redis) |
| JetBrains Rider / VS | Any | Open `CasewareCollaborate.sln` |

---

## Running Locally

```bash
cd TokenExchangeApi
dotnet run
# API available at https://localhost:5001
# Swagger UI:    https://localhost:5001/swagger
# OpenAPI JSON:  https://localhost:5001/swagger/v1/swagger.json
```

**Test the Token Exchange flow:**
```bash
# 1. Exchange tokens (returns a downstream JWT with the act claim)
curl -X POST https://localhost:5001/oauth/v2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token=<user-jwt>' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode 'actor_token=<service-jwt>' \
  --data-urlencode 'actor_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode 'scope=financial:read' \
  --data-urlencode 'audience=documents-service'

# 2. Use the downstream token to access the protected resource
curl https://localhost:5001/api/v1/workspaces/ws-42/financial-data \
  -H 'Authorization: Bearer <downstream-jwt>'
```

---

## Running Integration Tests

Docker must be running. Testcontainers pulls `redis:7-alpine` automatically.

```bash
cd TokenExchangeApi.Tests
dotnet test --logger "console;verbosity=normal"
```

The test suite proves end-to-end revocation: a JWT remains cryptographically valid but is rejected after `RevokeAsync()` removes the Redis epoch key.

---

## Project Structure

```
CasewareCollaborate.sln
├── TokenExchangeApi/                   ← Main API project
│   ├── Program.cs                      ← Composition root + endpoint definitions
│   ├── TokenExchangeService.cs         ← RFC 8693 implementation
│   ├── OboDelegationRequirement.cs     ← Authorization policy + handler
│   ├── IPermissionEpochStore.cs        ← L1/L2 epoch store (Null / Redis / Cached)
│   └── Models.cs                       ← Records, DTOs, JsonSerializerContext
└── TokenExchangeApi.Tests/             ← Integration test project
    ├── CollaborateWebFactory.cs         ← WebApplicationFactory + Testcontainers
    ├── JwtTestHelper.cs                 ← Test JWT factory
    └── PermissionRevocationTests.cs     ← 3 revocation scenarios
```

---

## AI Usage Transparency

The take-home test explicitly asks for transparency about AI tool usage. This submission used **Google Gemini (Antigravity)** as a pair-programming assistant throughout.

### Where AI helped
- Drafting the initial HLA mermaid diagram and RFC 8693 flow diagrams
- Generating boilerplate for `TokenValidationParameters` configuration and DI wiring
- Structuring the integration test fixture (`IAsyncLifetime` + Testcontainers lifecycle)
- Suggesting the `JsonClaimValueTypes.Json` approach for embedding the `act` claim as a nested JSON object (critical for RFC 8693 compliance)

### Where I corrected or overrode AI output
- AI initially suggested using `[Authorize]` attribute on Minimal API endpoints — corrected to `.RequireAuthorization("policyName")` which is the correct Minimal API pattern
- AI suggested `JwtBearerHandler` for the `/oauth/v2/token` endpoint — correctly overridden: the token is in the form body, not the `Authorization` header, so `JwtSecurityTokenHandler` must be used directly
- AI did not include `ClockSkew` configuration in `TokenValidationParameters` — added explicitly after recognizing it as a production requirement for distributed systems
- AI initially generated a `static partial class Program` — changed to `public partial class Program` to allow `WebApplicationFactory<Program>` from the test project

### How I would guide engineers using AI on this system
- **Use AI for structural scaffolding**, not for security decisions. Let it generate the DI wiring, but verify every `TokenValidationParameters` field manually against the RFC.
- **Treat AI output as a first draft**. For every JWT claim, audit claim mapping (`NameClaimType`, `RoleClaimType`) and validate that `ValidateIssuer`, `ValidateAudience`, and `ValidateLifetime` are all explicitly `true`.
- **Review allowlists manually**. AI will not know your specific `AllowedActorClientIds` — these must come from threat modeling, not generation.

### Where AI should NOT be trusted
- **Key management and rotation logic** — AI cannot reason about your specific HSM, KMS, or JWKS rotation schedule.
- **Threat modeling** — AI can list common attack patterns but cannot evaluate your specific tenant isolation model or data sensitivity.
- **Audit log schema** — AI will generate plausible schemas but cannot know what your compliance team requires for a SOC 2 or ISO 27001 audit trail.
- **Performance under load** — AI benchmarks are generalized; validate with your actual traffic shape (multi-tenant burst patterns differ significantly from single-tenant).

---

## Key Design Decisions (Quick Reference)

| Decision | Choice | Rationale |
|---|---|---|
| Token validation | `JwtSecurityTokenHandler` (framework) | No custom crypto; maps directly to what `JwtBearerHandler` uses internally |
| OBO pattern | RFC 8693 Token Exchange | Standards-compliant; `act` claim provides audit chain without custom headers |
| Revocation | Epoch versioning (not token denylist) | O(1) Redis read vs O(n) blocklist lookup; natural event-driven integration |
| L1 cache | `IMemoryCache` decorator, 2 s TTL | Eliminates ~98% of Redis reads; bounded revocation staleness |
| Policy enforcement | `IAuthorizationRequirement` + `AuthorizationHandler` | Framework-native; composable; testable without HTTP |
| JSON serialization | Source-generated `JsonSerializerContext` | AOT-safe; eliminates reflection on hot path |
