using System.Text.Json.Serialization;

namespace Caseware.Collaborate.TokenExchange;

// ── RFC 8693 Token Exchange Request ───────────────────────────────────────────

internal sealed record TokenExchangeRequest(
    string? GrantType,
    string? SubjectToken,
    string? SubjectTokenType,
    string? ActorToken,
    string? ActorTokenType,
    string? RequestedTokenType,
    string? Audience,
    string? Scope);

// ── RFC 8693 Success Response ─────────────────────────────────────────────────

internal sealed record TokenExchangeResponse(
    [property: JsonPropertyName("access_token")]      string AccessToken,
    [property: JsonPropertyName("issued_token_type")] string IssuedTokenType,
    [property: JsonPropertyName("token_type")]        string TokenType,
    [property: JsonPropertyName("expires_in")]        int    ExpiresIn);

// ── RFC 6749 §5.2 Error Response ──────────────────────────────────────────────

internal sealed record OAuthErrorResponse(
    [property: JsonPropertyName("error")]             string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);

// ── Internal Domain Types ─────────────────────────────────────────────────────

internal sealed record DownstreamToken(string TokenString, DateTime ExpiresAt);

/// <summary>
/// Lightweight discriminated union — avoids a OneOf dependency while giving
/// exhaustive pattern matching in C# 12.
/// </summary>
internal abstract record ExchangeResult
{
    internal sealed record Success(DownstreamToken Token) : ExchangeResult;
    internal sealed record Failure(OAuthErrorResponse Error) : ExchangeResult;
}

// ── act Claim Shape (RFC 8693 §4.1) ──────────────────────────────────────────
// The "act" claim is a JSON *object*, not a string. It identifies the
// intermediary service (the deputy) that performed the exchange.

internal sealed record ActClaim(
    [property: JsonPropertyName("sub")]             string  Sub,
    [property: JsonPropertyName("client_id")]       string  ClientId,
    [property: JsonPropertyName("service_version")] string? ServiceVersion);

// ── Downstream Resource Endpoint Response ─────────────────────────────────────

/// <summary>
/// Returned by GET /api/v1/workspaces/{id}/financial-data.
/// Both <see cref="Subject"/> and <see cref="DelegatedBy"/> are extracted from
/// the token's claims, proving full auditability of user AND intermediary service.
/// </summary>
internal sealed record AuditableAccessResponse(
    [property: JsonPropertyName("workspace_id")]  string      WorkspaceId,
    [property: JsonPropertyName("subject")]       string      Subject,
    [property: JsonPropertyName("delegated_by")]  ActorInfo   DelegatedBy,
    [property: JsonPropertyName("scope_used")]    string      ScopeUsed,
    [property: JsonPropertyName("data")]          FinancialData Data);

/// <summary>Auditable identity of the intermediary service extracted from the 'act' claim.</summary>
internal sealed record ActorInfo(
    [property: JsonPropertyName("sub")]             string  Sub,
    [property: JsonPropertyName("client_id")]       string? ClientId,
    [property: JsonPropertyName("service_version")] string? ServiceVersion);

/// <summary>Stub payload representing the protected financial resource.</summary>
internal sealed record FinancialData(
    [property: JsonPropertyName("workspace_id")] string WorkspaceId,
    [property: JsonPropertyName("message")]      string Message,
    [property: JsonPropertyName("note")]         string Note);

// Source-generated context — zero-reflection serialisation for all response types.
[JsonSerializable(typeof(ActClaim))]
[JsonSerializable(typeof(TokenExchangeResponse))]
[JsonSerializable(typeof(OAuthErrorResponse))]
[JsonSerializable(typeof(AuditableAccessResponse))]
[JsonSerializable(typeof(ActorInfo))]
[JsonSerializable(typeof(FinancialData))]
internal sealed partial class AppJsonSerializerContext : JsonSerializerContext { }

// ── Configuration ─────────────────────────────────────────────────────────────

internal sealed class JwtSettings
{
    /// <summary>Issuer ("iss") expected on all incoming tokens and stamped on issued tokens.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>Default audience for the internal Collaborate API gateway.</summary>
    public string InternalAudience { get; set; } = string.Empty;

    /// <summary>
    /// Base64-encoded HMAC-SHA256 signing key (≥256 bits).
    /// DEV ONLY — production must use an asymmetric RS256 key loaded from the IdP JWKS endpoint.
    /// </summary>
    public string SigningKeyBase64 { get; set; } = string.Empty;

    /// <summary>
    /// Explicit allowlist of service client IDs permitted to perform token exchange.
    /// Any actor_token whose client_id is NOT in this list is rejected with unauthorized_client.
    /// </summary>
    public string[] AllowedActorClientIds { get; set; } = [];

    /// <summary>Lifetime of the issued downstream token in minutes. Default: 10.</summary>
    public int DownstreamTtlMinutes { get; set; } = 10;

    /// <summary>
    /// When true, the OBO delegation handler validates the <c>perm_epoch</c> claim
    /// against the value stored in Redis (L2). A missing key or epoch mismatch
    /// results in 403 Forbidden — enabling sub-second revocation without re-issuing JWTs.
    /// Set to false in development when Redis is not available.
    /// </summary>
    public bool RequirePermissionEpochValidation { get; set; } = false;
}
