using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Caseware.Collaborate.TokenExchange;

/// <summary>
/// Implements RFC 8693 Token Exchange.
///
/// Validation is delegated entirely to <see cref="JwtSecurityTokenHandler"/> and
/// <see cref="TokenValidationParameters"/> — no custom signature verification or
/// cryptography is performed here.
/// </summary>
internal sealed class TokenExchangeService : ITokenExchangeService
{
    // ── RFC 8693 URNs ─────────────────────────────────────────────────────────
    private const string GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string TokenTypeJwt           = "urn:ietf:params:oauth:token-type:jwt";

    private readonly JwtSettings             _jwt;
    private readonly ILogger<TokenExchangeService> _logger;

    // JwtSecurityTokenHandler is thread-safe after construction; reuse as singleton.
    private readonly JwtSecurityTokenHandler _handler = new();

    public TokenExchangeService(
        IOptions<JwtSettings> jwtOptions,
        ILogger<TokenExchangeService> logger)
    {
        _jwt    = jwtOptions.Value;
        _logger = logger;
    }

    public Task<ExchangeResult> ExchangeAsync(TokenExchangeRequest request, CancellationToken ct = default)
    {
        // ── Step 1: Protocol conformance ──────────────────────────────────────
        if (request.GrantType != GrantTypeTokenExchange)
            return Fail("unsupported_grant_type",
                $"grant_type must be '{GrantTypeTokenExchange}'.");

        if (string.IsNullOrWhiteSpace(request.SubjectToken))
            return Fail("invalid_request", "subject_token is required.");

        if (string.IsNullOrWhiteSpace(request.ActorToken))
            return Fail("invalid_request", "actor_token is required.");

        // ── Step 2: Validate subject_token (the delegating user's JWT) ────────
        // Audience: the internal Collaborate API this request originally targeted.
        if (!TryValidateToken(
                tokenString:    request.SubjectToken,
                validAudiences: [_jwt.InternalAudience],
                principal:      out var subjectPrincipal,
                securityToken:  out var subjectJwt,
                error:          out var subjectError))
        {
            _logger.LogWarning("subject_token validation failed: {Error}", subjectError);
            return Fail("invalid_grant", $"subject_token is invalid: {subjectError}");
        }
        // Flow-analysis assertion: TryValidateToken sets principal to non-null on success.
        var validatedSubject = subjectPrincipal!;

        // ── Step 3: Validate actor_token (the calling service's JWT) ──────────
        // RFC 8693 §2.1: the actor token's audience is the token endpoint itself,
        // proving the service obtained it specifically for this exchange operation.
        if (!TryValidateToken(
                tokenString:    request.ActorToken,
                validAudiences: [$"{_jwt.Issuer}/token"],
                principal:      out var actorPrincipal,
                securityToken:  out _,
                error:          out var actorError))
        {
            _logger.LogWarning("actor_token validation failed: {Error}", actorError);
            return Fail("unauthorized_client", $"actor_token is invalid: {actorError}");
        }
        // Flow-analysis assertion: TryValidateToken sets principal to non-null on success.
        var validatedActor = actorPrincipal!;

        // ── Step 4: Actor allowlist — explicit delegation policy ───────────────
        // Only pre-registered internal services may act as deputies.
        // Fail closed: if client_id is absent, the request is rejected.
        var actorClientId = validatedActor.FindFirstValue("client_id")
                         ?? validatedActor.FindFirstValue(JwtRegisteredClaimNames.Sub)
                         ?? string.Empty;

        if (!_jwt.AllowedActorClientIds.Contains(actorClientId, StringComparer.Ordinal))
        {
            _logger.LogWarning(
                "Delegation denied. Actor '{ClientId}' is not in the allowlist.", actorClientId);
            return Fail("unauthorized_client",
                $"Service '{actorClientId}' is not permitted to perform token exchange.");
        }

        // ── Step 5: Scope narrowing — a deputy can NEVER escalate ─────────────
        var subjectScopes = ParseScopes(validatedSubject.FindFirstValue("scope"));
        var requestedScopes = ParseScopes(request.Scope);

        if (requestedScopes.Count > 0 && !requestedScopes.IsSubsetOf(subjectScopes))
        {
            var illegalScopes = string.Join(' ', requestedScopes.Except(subjectScopes));
            _logger.LogWarning(
                "Scope escalation attempt by '{ClientId}'. Illegal scopes: {Scopes}",
                actorClientId, illegalScopes);
            return Fail("invalid_scope",
                "Requested scope exceeds the permissions granted in the subject_token.");
        }

        // If no specific scope is requested, carry forward the subject's full scope.
        var effectiveScopes = requestedScopes.Count > 0 ? requestedScopes : subjectScopes;

        // ── Step 6: Issue the Downstream Token ────────────────────────────────
        var token = IssueDownstreamToken(
            subjectPrincipal: validatedSubject,
            actorPrincipal:   validatedActor,
            actorClientId:    actorClientId,
            targetAudience:   string.IsNullOrWhiteSpace(request.Audience)
                                  ? _jwt.InternalAudience
                                  : request.Audience,
            effectiveScopes:  effectiveScopes);

        _logger.LogInformation(
            "Token exchange issued. sub={Sub} act={ActorClientId} aud={Audience} scope=[{Scope}]",
            validatedSubject.FindFirstValue(JwtRegisteredClaimNames.Sub),
            actorClientId,
            request.Audience,
            string.Join(' ', effectiveScopes));

        return Task.FromResult<ExchangeResult>(new ExchangeResult.Success(token));
    }

    // ── Token Validation ──────────────────────────────────────────────────────
    // All signature verification, expiry checks, and claim validation are
    // performed exclusively by JwtSecurityTokenHandler — no custom crypto.

    private bool TryValidateToken(
        string            tokenString,
        string[]          validAudiences,
        out ClaimsPrincipal? principal,
        out JwtSecurityToken? securityToken,
        out string?       error)
    {
        var signingKey = new SymmetricSecurityKey(
            Convert.FromBase64String(_jwt.SigningKeyBase64));
        // NOTE: Production — replace SymmetricSecurityKey with an RsaSecurityKey
        // loaded from the IdP's JWKS endpoint for RS256 asymmetric validation.

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = _jwt.Issuer,
            ValidateAudience         = true,
            ValidAudiences           = validAudiences,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = signingKey,
            ClockSkew                = TimeSpan.FromSeconds(30),
            // Map "sub" so ClaimsPrincipal.Identity.Name resolves correctly.
            NameClaimType            = JwtRegisteredClaimNames.Sub,
        };

        try
        {
            principal     = _handler.ValidateToken(tokenString, validationParameters, out var raw);
            securityToken = (JwtSecurityToken)raw;
            error         = null;
            return true;
        }
        catch (SecurityTokenException ex)
        {
            // Catch only framework validation errors — let unexpected exceptions propagate.
            principal     = null;
            securityToken = null;
            error         = ex.Message;
            return false;
        }
    }

    // ── Downstream Token Issuance ─────────────────────────────────────────────

    private DownstreamToken IssueDownstreamToken(
        ClaimsPrincipal subjectPrincipal,
        ClaimsPrincipal actorPrincipal,
        string          actorClientId,
        string          targetAudience,
        HashSet<string> effectiveScopes)
    {
        var now     = DateTime.UtcNow;
        var expires = now.AddMinutes(_jwt.DownstreamTtlMinutes);

        // Preserve the original user's identity claims — immutable through delegation.
        var sub        = subjectPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub)!;
        var tenantId   = subjectPrincipal.FindFirstValue("tenant_id");
        var permEpoch  = subjectPrincipal.FindFirstValue("perm_epoch");
        var serviceVer = actorPrincipal.FindFirstValue("service_version");

        // Build the "act" claim as a JSON object per RFC 8693 §4.1.
        // JsonClaimValueTypes.Json tells the JwtSecurityToken serializer to
        // embed this as a nested JSON object — not an escaped string.
        var actClaim = new ActClaim(
            Sub:            $"svc:{actorClientId}",
            ClientId:       actorClientId,
            ServiceVersion: serviceVer);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            // jti provides a unique, traceable ID per issued token for audit logs.
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("scope", string.Join(' ', effectiveScopes)),
            // ↓ The critical "act" claim — identifies the deputy service, solving
            //   the Confused Deputy problem. The downstream API MUST log both
            //   "sub" (the user) and "act.sub" (the service) for full auditability.
            new("act",
                JsonSerializer.Serialize(actClaim, AppJsonSerializerContext.Default.ActClaim),
                JsonClaimValueTypes.Json),
        };

        // Carry forward contextual claims needed by downstream services.
        if (tenantId  is not null) claims.Add(new Claim("tenant_id",  tenantId));
        // perm_epoch is preserved so the downstream API participates in the same
        // event-driven revocation cycle defined in the L1/L2 caching ADR.
        if (permEpoch is not null) claims.Add(new Claim("perm_epoch", permEpoch));

        var signingKey = new SymmetricSecurityKey(
            Convert.FromBase64String(_jwt.SigningKeyBase64));
        // NOTE: Production — use RS256 (SigningCredentials with RsaSecurityKey).
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            issuer:             _jwt.Issuer,
            audience:           targetAudience,
            claims:             claims,
            notBefore:          now,
            expires:            expires,
            signingCredentials: credentials);

        return new DownstreamToken(
            TokenString: _handler.WriteToken(jwt),
            ExpiresAt:   expires);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static HashSet<string> ParseScopes(string? raw) =>
        raw?.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.Ordinal)
        ?? [];

    private static Task<ExchangeResult> Fail(string error, string description) =>
        Task.FromResult<ExchangeResult>(
            new ExchangeResult.Failure(new OAuthErrorResponse(error, description)));
}
