// Program.cs
using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Dapper;
using SPARC_API.DTOs;    // for LoginDto
using SPARC_API.Models; // POCOs / settings
using SPARC_API.Helpers; // Email services/templates
using System.Data;

var builder = WebApplication.CreateBuilder(args);

// In Development, user-secrets automatically override appsettings once
// you've run `dotnet user-secrets init` in this project.

// ─── 1. Typed settings & DI ──────────────────────────────────────
// Bind strongly-typed settings from appsettings sections
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("Smtp"));

// App services: email templating + SMTP sender
builder.Services.AddSingleton<EmailTemplateService>();
builder.Services.AddTransient<EmailService>();

// Database connection: create a new SqlConnection per request scope
builder.Services.AddTransient<IDbConnection>(_ =>
    new SqlConnection(builder.Configuration.GetConnectionString("DefaultConnection")));

// In-memory caching (for small hot data / templates)
builder.Services.AddMemoryCache();


// ─── 2. Built-in Rate Limiter ─────────────────────────────────────
// We define two policies:
//  - LoginPolicy: very strict to slow down credential stuffing (5/min per email/IP)
//  - DefaultPolicy: general API throughput limits (100/min per user or IP)
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("LoginPolicy", httpContext =>
    {
        // Prefer an email-derived key for login to throttle per-identity attempts.
        var key = (httpContext.Items["RateLimitKey"] as string)
                  ?? httpContext.Connection.RemoteIpAddress?.ToString()
                  ?? "anon";

        // Fixed window: 5 requests per minute, no queuing
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: key,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                AutoReplenishment = true,
                QueueLimit = 0
            });
    });

    options.AddPolicy("DefaultPolicy", httpContext =>
    {
        // Default key is client IP; if authenticated, switch to user subject (sub)
        string key = httpContext.Connection.RemoteIpAddress?.ToString() ?? "anon";
        if (httpContext.User.Identity?.IsAuthenticated == true)
        {
            var sub = httpContext.User.FindFirst("sub")?.Value;
            if (!string.IsNullOrWhiteSpace(sub))
                key = sub;
        }

        // Fixed window: 100 requests per minute, no queuing
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: key,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                AutoReplenishment = true,
                QueueLimit = 0
            });
    });

    // Unified 429 response when limits are exceeded
    options.OnRejected = async (rejCtx, token) =>
    {
        rejCtx.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await rejCtx.HttpContext.Response.WriteAsync(
            "Too many requests. Please try again later.", cancellationToken: token);
    };
});

// ─── 3. CORS ──────────────────────────────────────────────────────
// Load allowed origins from configuration and register a single default policy
var allowed = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
              ?? Array.Empty<string>();

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(allowed)     // Explicit allow-list
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials()));    // Needed if using cookies (e.g., accessToken)

// ─── 4. Authentication & Authorization ────────────────────────────
// Configure JWT bearer auth using symmetric signing key from config
var jwt = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()!;
var keyBytes = Encoding.UTF8.GetBytes(jwt.Key);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(opts =>
{
    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwt.Issuer,
        ValidateAudience = true,
        ValidAudience = jwt.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateLifetime = true, // enforce exp
        ClockSkew = TimeSpan.Zero // no grace period
    };

    // Allow HttpOnly cookie "accessToken" as an alternative to Authorization header.
    // Useful for browser clients and SignalR negotiate requests.
    opts.Events = new JwtBearerEvents
    {
        OnMessageReceived = ctx =>
        {
            if (!ctx.Request.Headers.ContainsKey("Authorization")
             && ctx.Request.Cookies.TryGetValue("accessToken", out var t))
            {
                ctx.Token = t;
            }
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

// ─── 5. MVC + JSON + Swagger ────────────────────────────────────
// Controllers with camelCase JSON serialization for payloads
builder.Services.AddControllers()
       .AddJsonOptions(o =>
           o.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase);

// Minimal OpenAPI setup for discoverability/testing
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // Map untyped JSON objects as "object" in schema
    c.MapType<JsonElement>(() => new OpenApiSchema { Type = "object" });
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "CAMP_API",
        Version = "v1",
    });
});

var app = builder.Build();

// ─── Pipeline ────────────────────────────────────────────────────
// Trust X-Forwarded-* headers from reverse proxies/load balancers (e.g., Nginx)
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

// CORS must appear before auth if using cookie-based JWTs
app.UseCors();

// Only force HTTPS redirection outside Development (assumes TLS termination)
if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();

if (app.Environment.IsDevelopment())
{
    // Interactive Swagger UI only in Development
    app.UseSwagger();
    app.UseSwaggerUI(c =>
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "CAMP_API v1"));
}

// AuthN/Z middlewares
app.UseAuthentication();
app.UseAuthorization();

// ─── Pre-limiter: asynchronously buffer & extract login-email ───
// We peek the login request body to derive a per-email throttle key for LoginPolicy.
app.Use(async (context, next) =>
{
    if (context.Request.Path.Equals("/api/auth/login", StringComparison.OrdinalIgnoreCase)
     && context.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
     && context.Request.ContentType?.Contains("application/json") == true)
    {
        context.Request.EnableBuffering();
        using var reader = new StreamReader(
            context.Request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        try
        {
            var dto = JsonSerializer.Deserialize<LoginDto>(body, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            if (!string.IsNullOrWhiteSpace(dto?.Email))
                context.Items["RateLimitKey"] = dto.Email.Trim().ToLowerInvariant();
        }
        catch { /* ignore parse failures */ }
    }
    await next();
});

// ─── 6. Turn on rate-limiting ────────────────────────────────────
// This enables the policies above. Controllers can apply them via [EnableRateLimiting("PolicyName")]
app.UseRateLimiter();

// ─── 7. SignalR hub + Controllers ────────────────────────────────
// (SignalR endpoints would be mapped here if/when added)

// Map attribute-routed controllers (e.g., [Route("api/...")])
app.MapControllers();

app.Run();
