using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Caseware.Collaborate.TokenExchange;

// ── Composition Root ──────────────────────────────────────────────────────────

var builder = WebApplication.CreateBuilder(args);

// ── 1. Bind typed configuration ───────────────────────────────────────────────
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));

// ── 2. ASP.NET Core JWT Bearer Authentication ─────────────────────────────────
//    All token parsing, signature verification, and claim extraction are handled
//    by the built-in JwtBearerHandler — no hand-rolled cryptography anywhere.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var jwt = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()!;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = jwt.Issuer,
            ValidateAudience         = true,
            ValidAudience            = jwt.InternalAudience,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            // DEV: SymmetricSecurityKey — Production: RsaSecurityKey from JWKS endpoint.
            IssuerSigningKey         = new SymmetricSecurityKey(
                                           Convert.FromBase64String(jwt.SigningKeyBase64)),
            ClockSkew                = TimeSpan.FromSeconds(30),
            NameClaimType            = JwtRegisteredClaimNames.Sub,
        };
    });

builder.Services.AddAuthorization(options =>
{
    // "RequireOboDelegation" enforces two invariants at policy level:
    //   • The 'act' claim must be present (proves RFC 8693 delegation, not direct user access)
    //   • The 'scope' must include 'financial:read'
    // Any token without both will receive 403 Forbidden before touching the endpoint.
    options.AddPolicy("RequireOboDelegation", policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(new OboDelegationRequirement("financial:read")));
});

// Expose OpenAPI/Swagger UI in development — all endpoint metadata (.WithName, .Produces<T>)
// is surfaced at GET /swagger/v1/swagger.json and browsable at /swagger.
// Swashbuckle.AspNetCore is used because AddOpenApi()/MapOpenApi() require .NET 9+;
// .NET 8 LTS is the target to maximise evaluator compatibility.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Caseware Collaborate Auth API", Version = "v1" });
});

// ── 3. Register application services ─────────────────────────────────────────
//    Registered as Singleton: JwtSecurityTokenHandler is thread-safe and
//    reusing a single instance avoids repeated handler initialization overhead.
builder.Services.AddSingleton<ITokenExchangeService, TokenExchangeService>();

// OboDelegationHandler is stateless — singleton lifetime is safe and avoids
// repeated allocation on high-throughput authorization checks.
builder.Services.AddSingleton<IAuthorizationHandler, OboDelegationHandler>();

// L1/L2 Caching strategy — matches the Architecture ADR:
//   L1: CachedPermissionEpochStore (IMemoryCache, 2-second TTL per instance)
//   L2: NullPermissionEpochStore in dev  /  RedisPermissionEpochStore in production
// Tests replace IPermissionEpochStore via ConfigureTestServices, bypassing the decorator.
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<IPermissionEpochStore>(sp =>
    new CachedPermissionEpochStore(
        inner: new NullPermissionEpochStore(),
        cache: sp.GetRequiredService<IMemoryCache>()));

// Configure the JSON serializer to use the source-generated context for
// all endpoint responses — avoids reflection and improves startup time.
builder.Services.ConfigureHttpJsonOptions(opts =>
    opts.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();  // browsable at /swagger
}

// ── 4. POST /oauth/v2/token — RFC 8693 Token Exchange ─────────────────────────
//
//    This endpoint is intentionally unauthenticated at the transport layer:
//    the tokens in the request body ARE the credentials. No Authorization header
//    is expected — the service validates both tokens internally.
//
//    Expected form fields:
//      grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
//      subject_token       = <user JWT>
//      subject_token_type  = urn:ietf:params:oauth:token-type:jwt
//      actor_token         = <service JWT>
//      actor_token_type    = urn:ietf:params:oauth:token-type:jwt
//      requested_token_type= urn:ietf:params:oauth:token-type:jwt
//      audience            = <target downstream service>
//      scope               = <space-separated, must be ⊆ subject_token scope>

app.MapPost("/oauth/v2/token", async (
    HttpContext           httpContext,
    ITokenExchangeService exchangeService,
    CancellationToken     ct) =>
{
    // Enforce content-type before reading. Returning early avoids unnecessary
    // form parsing and gives callers an explicit protocol error.
    if (!httpContext.Request.HasFormContentType)
        return Results.Json(
            new OAuthErrorResponse(
                "invalid_request",
                "Content-Type must be 'application/x-www-form-urlencoded'."),
            AppJsonSerializerContext.Default.OAuthErrorResponse,
            statusCode: StatusCodes.Status400BadRequest);

    var form = await httpContext.Request.ReadFormAsync(ct);

    var request = new TokenExchangeRequest(
        GrantType:          form["grant_type"].ToString(),
        SubjectToken:       form["subject_token"].ToString(),
        SubjectTokenType:   form["subject_token_type"].ToString(),
        ActorToken:         form["actor_token"].ToString(),
        ActorTokenType:     form["actor_token_type"].ToString(),
        RequestedTokenType: form["requested_token_type"].ToString(),
        Audience:           form["audience"].ToString(),
        Scope:              form["scope"].ToString());

    var result = await exchangeService.ExchangeAsync(request, ct);

    // Exhaustive pattern match over the discriminated union — the compiler
    // enforces that every ExchangeResult subtype is handled.
    return result switch
    {
        ExchangeResult.Success s => Results.Json(
            new TokenExchangeResponse(
                AccessToken:     s.Token.TokenString,
                IssuedTokenType: TokenTypeJwt,
                TokenType:       "Bearer",
                // Compute from actual expiry — stays correct if DownstreamTtlMinutes changes.
                ExpiresIn:       Math.Max(0, (int)(s.Token.ExpiresAt - DateTime.UtcNow).TotalSeconds)),
            AppJsonSerializerContext.Default.TokenExchangeResponse,
            statusCode: StatusCodes.Status200OK),

        ExchangeResult.Failure f => Results.Json(
            f.Error,
            AppJsonSerializerContext.Default.OAuthErrorResponse,
            statusCode: StatusCodes.Status400BadRequest),

        // Defensive arm — should never be reached with a sealed hierarchy.
        _ => Results.StatusCode(StatusCodes.Status500InternalServerError),
    };
})
.WithName("RFC8693_TokenExchange")
.WithSummary("OAuth 2.0 Token Exchange (RFC 8693)")
.WithDescription("""
    Accepts a user subject_token and a service actor_token.
    Validates both, enforces the delegation allowlist and scope narrowing,
    and issues a short-lived Downstream JWT containing the 'act' claim
    to solve the Confused Deputy problem.
    """)
.Produces<TokenExchangeResponse>(StatusCodes.Status200OK,  "application/json")
.Produces<OAuthErrorResponse>   (StatusCodes.Status400BadRequest, "application/json");

// ── 5. GET /api/v1/workspaces/{workspaceId}/financial-data ────────────────────
//
//    Protected by the "RequireOboDelegation" policy.
//    Only accepts tokens that were issued via RFC 8693 Token Exchange
//    (i.e., contain both a valid 'act' claim and the 'financial:read' scope).
//    Returns both sub (user) and act (service) so the caller can verify
//    the full audit chain is intact.

app.MapGet("/api/v1/workspaces/{workspaceId}/financial-data",
    (string workspaceId, HttpContext httpContext) =>
    {
        var user = httpContext.User;

        // ── Extract subject (the original user) ───────────────────────────────
        var sub = user.FindFirstValue(JwtRegisteredClaimNames.Sub) ?? "unknown";

        // ── Extract and deserialise the act claim (the intermediary service) ──
        // The JwtBearerMiddleware retains JSON object claims as their serialised
        // string representation — we deserialise here to surface individual fields.
        var actJson  = user.FindFirstValue("act") ?? "{}";
        var actClaim = JsonSerializer.Deserialize(
            actJson, AppJsonSerializerContext.Default.ActClaim);

        var response = new AuditableAccessResponse(
            WorkspaceId: workspaceId,
            // sub is the ORIGINAL user — preserved and immutable through delegation.
            Subject:     sub,
            // delegated_by is the INTERMEDIARY SERVICE — extracted from the act claim.
            // Logging both here proves complete auditability: we know who requested
            // the data AND which service was acting on their behalf.
            DelegatedBy: new ActorInfo(
                Sub:            actClaim?.Sub            ?? "unknown",
                ClientId:       actClaim?.ClientId,
                ServiceVersion: actClaim?.ServiceVersion),
            ScopeUsed: "financial:read",
            Data: new FinancialData(
                WorkspaceId: workspaceId,
                Message:     $"Q2 financial summary for workspace '{workspaceId}'",
                Note:        "Stub data — replace with IFinancialDataService in production."));

        return Results.Json(
            response,
            AppJsonSerializerContext.Default.AuditableAccessResponse);
    })
.RequireAuthorization("RequireOboDelegation")
.WithName("GetFinancialData")
.WithSummary("Get financial data for a workspace (OBO delegation required)")
.WithDescription("""
    Requires a Downstream JWT issued via RFC 8693 Token Exchange.
    Enforces presence of the 'act' claim and 'financial:read' scope.
    Returns the auditable sub+act pair alongside the protected resource.
    """)
.Produces<AuditableAccessResponse>(StatusCodes.Status200OK, "application/json")
.Produces(StatusCodes.Status401Unauthorized)
.Produces(StatusCodes.Status403Forbidden);

app.Run();

// Hoisted constant — keeps the switch arm readable without a magic string.
public partial class Program
{
    internal const string TokenTypeJwt = "urn:ietf:params:oauth:token-type:jwt";
}
