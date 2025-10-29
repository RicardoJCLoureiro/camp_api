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
using SPARC_API.Models;
using SPARC_API.Helpers;
using System.Data;

var builder = WebApplication.CreateBuilder(args);

// In Development, user-secrets automatically override appsettings once
// you've run `dotnet user-secrets init` in this project.

// ─── 1. Typed settings & DI ──────────────────────────────────────
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("Smtp"));

builder.Services.AddSingleton<EmailTemplateService>();
builder.Services.AddTransient<EmailService>();
builder.Services.AddTransient<IDbConnection>(_ =>
    new SqlConnection(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddMemoryCache();

// ─── 2. Built-in Rate Limiter ─────────────────────────────────────
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("LoginPolicy", httpContext =>
    {
        var key = (httpContext.Items["RateLimitKey"] as string)
                  ?? httpContext.Connection.RemoteIpAddress?.ToString()
                  ?? "anon";
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
        string key = httpContext.Connection.RemoteIpAddress?.ToString() ?? "anon";
        if (httpContext.User.Identity?.IsAuthenticated == true)
        {
            var sub = httpContext.User.FindFirst("sub")?.Value;
            if (!string.IsNullOrWhiteSpace(sub))
                key = sub;
        }
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

    options.OnRejected = async (rejCtx, token) =>
    {
        rejCtx.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await rejCtx.HttpContext.Response.WriteAsync(
            "Too many requests. Please try again later.", cancellationToken: token);
    };
});

// ─── 3. CORS ──────────────────────────────────────────────────────
var allowed = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
              ?? Array.Empty<string>();
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(allowed)
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials()));

// ─── 4. Authentication & Authorization ────────────────────────────
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
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };

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
builder.Services.AddControllers()
       .AddJsonOptions(o =>
           o.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.MapType<JsonElement>(() => new OpenApiSchema { Type = "object" });
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "CAMP_API",
        Version = "v1",
    });
});

var app = builder.Build();

// ─── Pipeline ────────────────────────────────────────────────────
// Forwarded headers: trust common proxies/load balancers
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseCors();

if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "CAMP_API v1"));
}

app.UseAuthentication();
app.UseAuthorization();

// ─── Pre-limiter: asynchronously buffer & extract login-email ───
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
app.UseRateLimiter();

// ─── 7. Controllers ──────────────────────────────────────────────
app.MapControllers();

app.Run();
