// Controllers/MfaController.cs
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OtpNet;
using SPARC_API.Helpers;
using SPARC_API.Models;
using System;
using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace SPARC_API.Controllers
{
    /// <summary>
    /// Manages user opt-in to MFA:
    /// - POST /api/mfa/setup: generates a TOTP secret and returns the otpauth URI + Base32 secret
    /// - POST /api/mfa/confirm: verifies a TOTP code and enables MFA
    /// All calls are logged (request/response) via LoggingHelper.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class MfaController : ControllerBase
    {
        private readonly IDbConnection _db;
        private readonly ILogger<MfaController> _logger;
        private readonly JwtSettings _jwt;

        public MfaController(
            IDbConnection db,
            ILogger<MfaController> logger,
            IOptions<JwtSettings> jwtOptions)
        {
            _db = db;
            _logger = logger;
            _jwt = jwtOptions.Value;
        }

        /// <summary>
        /// Step 1: Generate a new MFA secret for the authenticated user
        /// and return the otpauth URI plus the Base32 secret.
        /// </summary>
        [Authorize]
        [HttpPost("setup")]
        public async Task<IActionResult> Setup()
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper
                .LogEndpointCallAsync(_db, "MfaController.Setup", HttpContext.Request.Path);
            string reqLog = "{}";
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                // 1) Extract userId & email from token
                var subClaim = User.FindFirstValue(ClaimTypes.NameIdentifier)
                                  ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                var emailClaim = User.FindFirstValue(ClaimTypes.Email)
                                  ?? User.FindFirstValue(JwtRegisteredClaimNames.Email);
                if (string.IsNullOrEmpty(subClaim)
                 || !int.TryParse(subClaim, out var userId)
                 || string.IsNullOrEmpty(emailClaim))
                {
                    statusCode = 401;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid token claims." });
                    return Unauthorized(new { error = "Invalid token claims." });
                }

                // 2) Generate and store a new Base32 secret
                byte[] secretBytes = KeyGeneration.GenerateRandomKey(20);
                string secret = Base32Encoding.ToString(secretBytes);
                await _db.ExecuteAsync(
                    "UPDATE dbo.USERS SET MFASecret = @Secret WHERE USER_ID = @Id;",
                    new { Secret = secret, Id = userId }
                );

                // 3) Build the otpauth URI using configured issuer
                //    (Keeps compatibility with most authenticator apps)
                string issuer = string.IsNullOrWhiteSpace(_jwt.Issuer) ? "SPARC_API" : _jwt.Issuer;
                string uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(emailClaim)}"
                           + $"?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30";

                // 4) Return secret + URI (do NOT log the secret)
                resLog = JsonSerializer.Serialize(new { issued = true });
                return Ok(new { secret, uri });
            }
            catch (Exception ex)
            {
                statusCode = 500;
                error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(
                    _db,
                    endpointLogId,
                    reqLog,
                    resLog,
                    statusCode,
                    error,
                    (int)sw.ElapsedMilliseconds
                );
            }
        }

        /// <summary>
        /// Step 2: Confirm the TOTP code. If valid, enables MFA for the authenticated user.
        /// </summary>
        [Authorize]
        [HttpPost("confirm")]
        public async Task<IActionResult> Confirm([FromBody] string code)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper
                .LogEndpointCallAsync(_db, "MfaController.Confirm", HttpContext.Request.Path);
            // redact the code in logs
            string reqLog = JsonSerializer.Serialize(new { Code = "REDACTED" });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                // 1) Extract userId
                var subClaim = User.FindFirstValue(ClaimTypes.NameIdentifier)
                             ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                if (string.IsNullOrEmpty(subClaim)
                 || !int.TryParse(subClaim, out var userId))
                {
                    statusCode = 401;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid token claims." });
                    return Unauthorized(new { error = "Invalid token claims." });
                }

                // 2) Retrieve stored secret
                string? secret = await _db.QuerySingleOrDefaultAsync<string?>(
                    "SELECT MFASecret FROM dbo.USERS WHERE USER_ID = @Id;",
                    new { Id = userId }
                );
                if (string.IsNullOrEmpty(secret))
                {
                    statusCode = 400;
                    resLog = JsonSerializer.Serialize(new { error = "MFA not initiated." });
                    return BadRequest(new { error = "MFA not initiated." });
                }

                // 3) Verify TOTP code
                var totp = new Totp(Base32Encoding.ToBytes(secret));
                if (!totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay))
                {
                    statusCode = 400;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid MFA code." });
                    return BadRequest(new { error = "Invalid MFA code." });
                }

                // 4) Enable MFA flag
                await _db.ExecuteAsync(
                    "UPDATE dbo.USERS SET IsMfaEnabled = 1 WHERE USER_ID = @Id;",
                    new { Id = userId }
                );

                resLog = JsonSerializer.Serialize(new { message = "MFA enabled." });
                return Ok(new { message = "MFA enabled." });
            }
            catch (Exception ex)
            {
                statusCode = 500;
                error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(
                    _db,
                    endpointLogId,
                    reqLog,
                    resLog,
                    statusCode,
                    error,
                    (int)sw.ElapsedMilliseconds
                );
            }
        }
    }
}
