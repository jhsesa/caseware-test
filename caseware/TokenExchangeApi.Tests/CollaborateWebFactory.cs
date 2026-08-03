using Caseware.Collaborate.TokenExchange;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;
using Testcontainers.Redis;
using Xunit;

namespace Caseware.Collaborate.Tests;

/// <summary>
/// xUnit class fixture that owns the full integration test environment:
///
///   1. Starts a real Redis 7 container via Testcontainers before any test runs.
///   2. Spins up the ASP.NET Core pipeline in-process via WebApplicationFactory.
///   3. Replaces the registered <see cref="IPermissionEpochStore"/> with a real
///      <see cref="RedisPermissionEpochStore"/> pointing at the test container,
///      so tests exercise the actual Redis code path — not a mock.
///   4. Overrides configuration to enable strict epoch validation, matching
///      the production posture without touching appsettings files.
///
/// Implements <see cref="IAsyncLifetime"/> so xUnit calls InitializeAsync before
/// the first test and DisposeAsync after the last, stopping the container cleanly.
/// </summary>
public sealed class CollaborateWebFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    // Testcontainers manages the Docker container lifecycle automatically.
    // redis:7-alpine is a small, deterministic image suited for CI.
    private readonly RedisContainer _redisContainer = new RedisBuilder()
        .WithImage("redis:7-alpine")
        .Build();

    // Exposed so tests can seed/revoke epochs directly.
    // internal: IPermissionEpochStore is internal; all consumers are in this assembly.
    internal IPermissionEpochStore EpochStore { get; private set; } = null!;

    // ── IAsyncLifetime ────────────────────────────────────────────────────────

    public async Task InitializeAsync()
    {
        // Start the container. Testcontainers blocks until Redis is healthy.
        await _redisContainer.StartAsync();

        // Build the real Redis epoch store pointing at the test container.
        // This same instance is injected into DI inside ConfigureWebHost.
        var multiplexer = await ConnectionMultiplexer.ConnectAsync(
            _redisContainer.GetConnectionString());

        EpochStore = new RedisPermissionEpochStore(multiplexer);
    }

    public new async Task DisposeAsync()
    {
        await _redisContainer.DisposeAsync();
        await base.DisposeAsync();
    }

    // ── WebApplicationFactory Configuration ───────────────────────────────────

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            // In-memory overrides — applied last, so they win over appsettings files.
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Tokens created by JwtTestHelper target "documents-service".
                ["Jwt:InternalAudience"]              = "documents-service",

                // Activate epoch validation — this is the production posture.
                // Without this override the NullPermissionEpochStore skips the check.
                ["Jwt:RequirePermissionEpochValidation"] = "true",
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Replace the NullPermissionEpochStore registered in Program.cs with
            // the real Redis-backed store pointing at the Testcontainers instance.
            // RemoveAll ensures we don't end up with two registrations.
            services.RemoveAll<IPermissionEpochStore>();
            services.AddSingleton(EpochStore);
        });
    }
}
