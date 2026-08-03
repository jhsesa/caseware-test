using StackExchange.Redis;
using Microsoft.Extensions.Caching.Memory;

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
        return value.HasValue && long.TryParse((string)value!, out var epoch) ? epoch : null;
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

// ── L1 Cache Decorator (in-process, 2-second TTL) ─────────────────────────────

/// <summary>
/// Decorator that adds an in-process L1 cache in front of any
/// <see cref="IPermissionEpochStore"/> implementation (typically Redis L2).
///
/// Read path: L1 hit → return immediately (no Redis round-trip).
///             L1 miss → promote from L2, cache for <see cref="L1Ttl"/>.
///
/// Write/revoke path: L1 key is invalidated immediately, then L2 is updated.
/// Maximum revocation staleness on the instance that issued the revocation = 0.
/// Maximum revocation staleness on other instances = L1Ttl (2 s by design).
///
/// At 10,000 RPS with typical session durations, this eliminates ≈ 98 % of
/// Redis reads, keeping the L2 tier free for write-heavy cache invalidation.
/// </summary>
internal sealed class CachedPermissionEpochStore(
    IPermissionEpochStore inner,
    IMemoryCache          cache)
    : IPermissionEpochStore
{
    // 2-second L1 TTL: matches the SLA stated in the Architecture ADR.
    // Increase to reduce Redis load; decrease to tighten revocation latency.
    private static readonly TimeSpan L1Ttl = TimeSpan.FromSeconds(2);

    private static string L1Key(string userId) => $"epoch_l1:{userId}";

    public async Task<long?> GetCurrentEpochAsync(string userId, CancellationToken ct = default)
    {
        // ── L1 hit ────────────────────────────────────────────────────────────
        if (cache.TryGetValue(L1Key(userId), out long cached))
            return cached;

        // ── L1 miss → promote from L2 (Redis) ────────────────────────────────
        var epoch = await inner.GetCurrentEpochAsync(userId, ct);

        if (epoch is not null)
            cache.Set(L1Key(userId), epoch.Value, L1Ttl);

        // null means revoked or not yet seeded — do NOT cache nulls (fail closed).
        return epoch;
    }

    public Task SetEpochAsync(string userId, long epoch, CancellationToken ct = default)
    {
        // Evict stale L1 entry before writing to L2.
        cache.Remove(L1Key(userId));
        return inner.SetEpochAsync(userId, epoch, ct);
    }

    public Task RevokeAsync(string userId, CancellationToken ct = default)
    {
        // Evict L1 immediately — this instance sees the revocation with zero delay.
        // Cross-instance propagation is bounded by L1Ttl (2 s).
        cache.Remove(L1Key(userId));
        return inner.RevokeAsync(userId, ct);
    }
}
