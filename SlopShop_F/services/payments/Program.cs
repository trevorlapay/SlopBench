using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using SlopShop.Payments.Services;

static string RequiredSetting(IConfiguration configuration, string key)
{
    string? value = configuration[key];
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException($"missing required configuration: {key}");
    }
    return value;
}

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Configuration comes from the environment only.
builder.Configuration.AddEnvironmentVariables(prefix: "PAYMENTS_");

builder.Services.AddNpgsqlDataSource(RequiredSetting(builder.Configuration, "DATABASE_URL"));
builder.Services.AddSingleton(_ => TokenVault.FromEnvironment());
builder.Services.AddControllers();
builder.Services.AddProblemDetails();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = RequiredSetting(builder.Configuration, "JWT_AUTHORITY");
        options.Audience = RequiredSetting(builder.Configuration, "JWT_AUDIENCE");
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            // The identity service signs with RS256.
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.Identity?.Name ?? context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
});

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;
    // Only the mesh ingress is trusted to set forwarding headers.
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
    options.AllowedHosts.Add("payments.internal.slopshop.example");
});

WebApplication app = builder.Build();

app.UseForwardedHeaders();

// Unhandled exceptions become an RFC 9457 problem document.
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseHsts();
app.UseHttpsRedirection();

app.Use(async (context, next) =>
{
    IHeaderDictionary headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["Cache-Control"] = "no-store";
    headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    await next();
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

await app.RunAsync();
