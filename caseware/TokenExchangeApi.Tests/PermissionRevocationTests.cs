using System.Net;
using System.Text.Json;
using Caseware.Collaborate.TokenExchange;
using Xunit;

namespace Caseware.Collaborate.Tests;

/// <summary>
/// Integration tests for the permission revocation flow.
///
/// These tests exercise the FULL stack in-process:
///   HTTP request → JWT Bearer middleware → OboDelegationHandler → Redis epoch check → endpoint
///
/// A real Redis container is managed by <see cref="CollaborateWebFactory"/>.
/// No mocks are used — this is the behaviour that will run in production.
/// </summary>
public sealed class PermissionRevocationTests : IClassFixture<CollaborateWebFactory>
{
    private readonly HttpClient              _client;
    private readonly IPermissionEpochStore   _epochStore;

    public PermissionRevocationTests(CollaborateWebFactory factory)
    {
        _client     = factory.CreateClient();
        _epochStore = factory.EpochStore;
    }

    // ── Core Revocation Test ──────────────────────────────────────────────────

    /// <summary>
    /// SCENARIO: A user's permissions are revoked mid-session.
    ///
    /// GIVEN  a Downstream JWT with perm_epoch=1 and a valid act claim
    ///   AND  Redis contains epoch=1 for that user  (seeded at permission grant time)
    ///
    /// WHEN   the user makes a first request                → expect 200 OK
    ///   AND  a perm.revoked event fires (simulated here)  → Redis key is deleted
    ///   AND  the user makes a second request with the SAME JWT
    ///
    /// THEN   the second response must be 403 Forbidden.
    ///
    /// WHY THIS MATTERS: The JWT has not expired — it is still cryptographically
    /// valid. Only the Redis epoch key was removed. This proves revocation is
    /// effective within the L1 TTL window (≤2 s) without reissuing the JWT.
    /// </summary>
    [Fact]
    public async Task WhenPermissionsRevoked_SubsequentRequest_Returns403()
    {
        // ── Arrange ───────────────────────────────────────────────────────────

        const string userId       = "user-integration-001";
        const long   initialEpoch = 1L;
        const string workspaceId  = "ws-integration-42";
        const string url          = $"/api/v1/workspaces/{workspaceId}/financial-data";

        // Seed L2 (Redis): epoch=1 is currently valid for this user.
        // In production this is written by the permission grant flow.
        await _epochStore.SetEpochAsync(userId, initialEpoch);

        // Mint a Downstream JWT: sub=userId, perm_epoch=1, act=reporting-service, scope=financial:read
        var token = JwtTestHelper.CreateDownstreamToken(
            userId:    userId,
            permEpoch: initialEpoch,
            actSub:    "svc:reporting-service",
            scope:     "financial:read");

        // ── Act & Assert — Step 1: valid epoch → 200 OK ───────────────────────

        var firstResponse = await _client.SendAsync(JwtTestHelper.AuthorizedGet(url, token));

        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        // Verify the audit claims are present in the response body —
        // proving sub (user) and act (service) are both captured.
        var body = await ParseResponseAsync(firstResponse);

        Assert.Equal(userId,                           body.Subject);
        Assert.Equal("svc:reporting-service",          body.DelegatedBy.Sub);
        Assert.Equal("financial:read",                 body.ScopeUsed);
        Assert.Equal(workspaceId,                      body.WorkspaceId);

        // ── Simulate perm.revoked event ───────────────────────────────────────
        //
        // In production, this is triggered by an event bus consumer that:
        //   1. Updates permissions in the DB.
        //   2. Publishes a perm.revoked event.
        //   3. The consumer calls IPermissionEpochStore.RevokeAsync() here.
        //   4. A separate event drops active WebSocket connections for this user.
        //
        // We call RevokeAsync directly to isolate the HTTP revocation path.
        await _epochStore.RevokeAsync(userId);

        // ── Act & Assert — Step 2: epoch revoked → 403 Forbidden ─────────────
        //
        // The JWT is still valid (not expired, signature correct), but the
        // Redis key no longer exists. OboDelegationHandler sees storedEpoch=null
        // and fails closed → 403 Forbidden.

        var secondResponse = await _client.SendAsync(JwtTestHelper.AuthorizedGet(url, token));

        Assert.Equal(HttpStatusCode.Forbidden, secondResponse.StatusCode);
    }

    // ── Supplementary: No act claim → 403 ────────────────────────────────────

    /// <summary>
    /// A token presented directly by a user (no act claim) must be rejected,
    /// even if it carries the correct scope. This ensures the Confused Deputy
    /// protection cannot be bypassed by stripping the act claim.
    /// </summary>
    [Fact]
    public async Task WhenActClaimMissing_Request_Returns403()
    {
        const string url = "/api/v1/workspaces/ws-99/financial-data";

        // Build a token that has the right scope but NO act claim —
        // simulates a user calling the downstream API directly.
        var signingKey  = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            Convert.FromBase64String("ZGV2T25seVNpZ25pbmdLZXlEb05vdFVzZUluUHJvZGQ="));
        var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
            signingKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);

        var directUserToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer:             "https://idp.caseware.com",
            audience:           "documents-service",
            claims:             [
                new System.Security.Claims.Claim("sub",   "user-direct-001"),
                new System.Security.Claims.Claim("scope", "financial:read"),
                // Deliberately no "act" claim — this is the Confused Deputy scenario.
            ],
            notBefore:          DateTime.UtcNow,
            expires:            DateTime.UtcNow.AddMinutes(10),
            signingCredentials: credentials);

        var tokenString = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler()
            .WriteToken(directUserToken);

        var response = await _client.SendAsync(JwtTestHelper.AuthorizedGet(url, tokenString));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ── Supplementary: Wrong scope → 403 ─────────────────────────────────────

    /// <summary>
    /// A delegated token with the correct act claim but the wrong scope
    /// must be rejected. Proves scope narrowing is enforced at the resource.
    /// </summary>
    [Fact]
    public async Task WhenScopeInsufficient_Request_Returns403()
    {
        const string url   = "/api/v1/workspaces/ws-99/financial-data";
        const string userId = "user-scope-test-001";

        await _epochStore.SetEpochAsync(userId, 1L);

        // Token has act claim but wrong scope (documents:read instead of financial:read)
        var token = JwtTestHelper.CreateDownstreamToken(
            userId:    userId,
            permEpoch: 1L,
            actSub:    "svc:reporting-service",
            scope:     "documents:read");      // ← wrong scope

        var response = await _client.SendAsync(JwtTestHelper.AuthorizedGet(url, token));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    // Local DTO mirrors AuditableAccessResponse — tests should not depend on
    // the internal type directly; deserialising to a local record is more robust.
    private sealed record ResponseBody(
        string     WorkspaceId,
        string     Subject,
        ActorDto   DelegatedBy,
        string     ScopeUsed);

    private sealed record ActorDto(string Sub);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static async Task<ResponseBody> ParseResponseAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<ResponseBody>(json, JsonOpts)
               ?? throw new InvalidOperationException($"Could not deserialise response: {json}");
    }
}
