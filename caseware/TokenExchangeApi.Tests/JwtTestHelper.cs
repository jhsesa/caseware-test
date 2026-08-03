using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Caseware.Collaborate.Tests;

/// <summary>
/// Mints cryptographically valid test JWTs using the same dev signing key
/// configured in appsettings.Development.json.
///
/// Keeping JWT creation here (not inline in tests) means a key change only
/// requires editing one file — and test intent stays readable.
/// </summary>
internal static class JwtTestHelper
{
    // Must exactly match appsettings.Development.json → Jwt:SigningKeyBase64.
    // Decodes to: "devOnlySigningKeyDoNotUseInProdd" (32 bytes / 256 bits).
    private const string DevSigningKeyBase64 = "ZGV2T25seVNpZ25pbmdLZXlEb05vdFVzZUluUHJvZGQ=";
    private const string Issuer              = "https://idp.caseware.com";

    private static readonly JwtSecurityTokenHandler Handler = new();

    // ── Token Factory ─────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a Downstream Token as if it had been issued by POST /oauth/v2/token.
    /// Includes sub, perm_epoch, a JSON act claim, scope, tenant_id, and jti.
    /// </summary>
    internal static string CreateDownstreamToken(
        string userId,
        long   permEpoch,
        string actSub,
        string scope,
        string audience   = "documents-service",
        int    ttlMinutes = 10)
    {
        var signingKey  = new SymmetricSecurityKey(Convert.FromBase64String(DevSigningKeyBase64));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        // Build the act claim as a JSON object — mirrors exactly what TokenExchangeService does.
        var actJson = $$"""{"sub":"{{actSub}}","client_id":"reporting-service","service_version":"2.4.1"}""";

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("perm_epoch", permEpoch.ToString()),
            new("tenant_id",  "acme-corp"),
            new("scope",      scope),
            // JsonClaimValueTypes.Json → embedded as a JSON object, not an escaped string.
            new("act",        actJson, JsonClaimValueTypes.Json),
        };

        var token = new JwtSecurityToken(
            issuer:             Issuer,
            audience:           audience,
            claims:             claims,
            notBefore:          DateTime.UtcNow,
            expires:            DateTime.UtcNow.AddMinutes(ttlMinutes),
            signingCredentials: credentials);

        return Handler.WriteToken(token);
    }

    // ── Request Builder ───────────────────────────────────────────────────────

    /// <summary>Wraps a GET request with a Bearer token Authorization header.</summary>
    internal static HttpRequestMessage AuthorizedGet(string url, string bearerToken) =>
        new(HttpMethod.Get, url)
        {
            Headers = { Authorization = new("Bearer", bearerToken) },
        };
}
