using StackExchange.Redis;

namespace Caseware.Collaborate.TokenExchange;

// ── Contract ──────────────────────────────────────────────────────────────────

/// <summary>
/// L2 permission epoch store.
/// Stores a monotonically increasing integer per user in Redis.
/// If the epoch in the JWT does not match the stored value, the token is
/// considered revoked and access is denied immediately — no DB query needed.
/// A missing key is also treated as revoked when epoch validation is enabled.
/// </summary>
internal interface IPermissionEpochStore
{
    /// <summary>Returns the current epoch, or null if the key does not exist (revoked).</summary>
    Task<long?> GetCurrentEpochAsync(string userId, CancellationToken ct = default);

    /// <summary>Seeds or updates the epoch (called on permission grant or after DB write).</summary>
    Task SetEpochAsync(string userId, long epoch, CancellationToken ct = default);

    /// <summary>
    /// Revokes the user's epoch by deleting the Redis key.
    /// Any in-flight JWT carrying the old epoch will be rejected on next check.
    /// </summary>
    Task RevokeAsync(string userId, CancellationToken ct = default);
}

// ── No-op Implementation (development / Redis not configured) ─────────────────

/// <summary>
/// No-op store used when Redis is not configured.
/// Always returns null — epoch validation MUST be disabled via
/// <see cref="JwtSettings.RequirePermissionEpochValidation"/> in this mode.
/// </summary>
internal sealed class NullPermissionEpochStore : IPermissionEpochStore
{
    public Task<long?> GetCurrentEpochAsync(string userId, CancellationToken ct = default)
        => Task.FromResult<long?>(null);

    public Task SetEpochAsync(string userId, long epoch, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task RevokeAsync(string userId, CancellationToken ct = default)
        => Task.CompletedTask;
}

// ── Redis Implementation (L2 cache tier) ─────────────────────────────────────

/// <summary>
/// Redis-backed epoch store. Keys are namespaced per user with a 24-hour TTL;
/// active sessions will refresh the TTL via <see cref="SetEpochAsync"/>.
/// </summary>
internal sealed class RedisPermissionEpochStore(IConnectionMultiplexer redis)
    : IPermissionEpochStore
{
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromHours(24);
    private static string Key(string userId) => $"perm_epoch:{userId}";

    public async Task<long?> GetCurrentEpochAsync(string userId, CancellationToken ct = default)
    {
        var value = await redis.GetDatabase().StringGetAsync(Key(userId));
        return value.HasValue && long.TryParse(value, out var epoch) ? epoch : null;
    }

    public async Task SetEpochAsync(string userId, long epoch, CancellationToken ct = default) =>
        await redis.GetDatabase().StringSetAsync(Key(userId), epoch, DefaultTtl);

    /// <summary>
    /// Deletes the epoch key. With <see cref="JwtSettings.RequirePermissionEpochValidation"/>
    /// enabled, any request bearing the old epoch will receive 403 Forbidden immediately.
    /// </summary>
    public async Task RevokeAsync(string userId, CancellationToken ct = default) =>
        await redis.GetDatabase().KeyDeleteAsync(Key(userId));
}
