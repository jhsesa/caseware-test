using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Caseware.Collaborate.TokenExchange;

// ── Requirement ───────────────────────────────────────────────────────────────

/// <summary>
/// Authorization requirement that enforces three invariants on the incoming JWT,
/// plus an optional L2 Redis epoch check:
///   1. The <c>act</c> claim must be present and contain a valid <c>sub</c>.
///   2. The <c>scope</c> claim must include <see cref="RequiredScope"/>.
///   3. (When enabled) <c>perm_epoch</c> must match the stored epoch in Redis.
///      A missing Redis key or mismatch causes immediate 403 — sub-second revocation.
/// </summary>
internal sealed class OboDelegationRequirement : IAuthorizationRequirement
{
    public OboDelegationRequirement(string requiredScope) => RequiredScope = requiredScope;

    public string RequiredScope { get; }
}

// ── Handler ───────────────────────────────────────────────────────────────────

internal sealed class OboDelegationHandler(
    ILogger<OboDelegationHandler> logger,
    IPermissionEpochStore         epochStore,
    IOptions<JwtSettings>         jwtOptions)
    : AuthorizationHandler<OboDelegationRequirement>
{
    private readonly JwtSettings _jwt = jwtOptions.Value;

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OboDelegationRequirement    requirement)
    {
        var user = context.User;

        // ── Check 1: "act" claim must exist ──────────────────────────────────
        var actJson = user.FindFirstValue("act");
        if (string.IsNullOrWhiteSpace(actJson))
        {
            logger.LogWarning(
                "OBO policy failed: 'act' claim absent. sub={Sub}",
                user.FindFirstValue(JwtRegisteredClaimNames.Sub));
            return;
        }

        // ── Check 2: "act" must be a valid JSON object with a non-empty sub ──
        ActClaim? actClaim;
        try
        {
            actClaim = JsonSerializer.Deserialize(
                actJson, AppJsonSerializerContext.Default.ActClaim);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "OBO policy failed: 'act' claim is malformed JSON.");
            return;
        }

        if (string.IsNullOrWhiteSpace(actClaim?.Sub))
        {
            logger.LogWarning("OBO policy failed: 'act.sub' is absent or empty.");
            return;
        }

        // ── Check 3: required scope must be present ───────────────────────────
        var grantedScopes = (user.FindFirstValue("scope") ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (!grantedScopes.Contains(requirement.RequiredScope, StringComparer.Ordinal))
        {
            logger.LogWarning(
                "OBO policy failed: scope '{Required}' not in token. Granted=[{Granted}] act={ActSub}",
                requirement.RequiredScope,
                string.Join(' ', grantedScopes),
                actClaim.Sub);
            return;
        }

        // ── Check 4: perm_epoch must match the L2 Redis store ─────────────────
        // This is the revocation check. When a user's permissions change, the
        // event consumer calls IPermissionEpochStore.RevokeAsync(), removing the
        // Redis key. Any subsequent request carrying the old epoch is rejected
        // here with 403, achieving sub-second revocation without re-issuing JWTs.
        //
        // Disabled in development (RequirePermissionEpochValidation = false)
        // to allow running without a Redis dependency.
        if (_jwt.RequirePermissionEpochValidation)
        {
            var userId      = user.FindFirstValue(JwtRegisteredClaimNames.Sub);
            var jwtEpochStr = user.FindFirstValue("perm_epoch");

            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(jwtEpochStr))
            {
                if (!long.TryParse(jwtEpochStr, out var jwtEpoch))
                {
                    logger.LogWarning(
                        "OBO policy failed: 'perm_epoch' is not a valid integer. sub={Sub}", userId);
                    return;
                }

                var storedEpoch = await epochStore.GetCurrentEpochAsync(userId);

                // Fail closed on both null (key revoked/deleted) and mismatch.
                if (storedEpoch is null || storedEpoch.Value != jwtEpoch)
                {
                    logger.LogWarning(
                        "OBO policy failed: perm_epoch mismatch or key revoked. " +
                        "jwt={JwtEpoch} stored={StoredEpoch} sub={Sub} act={ActSub}",
                        jwtEpoch, storedEpoch?.ToString() ?? "null (revoked)", userId, actClaim.Sub);
                    return;
                }
            }
        }

        logger.LogDebug(
            "OBO policy satisfied. sub={Sub} act={ActSub} scope={Scope}",
            user.FindFirstValue(JwtRegisteredClaimNames.Sub),
            actClaim.Sub,
            requirement.RequiredScope);

        context.Succeed(requirement);
    }
}
