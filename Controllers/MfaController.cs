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
    /// Standalone MFA management endpoints (setup + confirm).
    /// Intended for authenticated users adding MFA after initial signup/login.
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
        /// Step 1: Generate Base32 secret and otpauth URI for the current user.
        /// Stores the secret server-side; client uses it to configure Authenticator app.
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
                // Pull user id/email from JWT.
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

                // Generate random secret and persist against the user.
                byte[] secretBytes = KeyGeneration.GenerateRandomKey(20);
                string secret = Base32Encoding.ToString(secretBytes);
                await _db.ExecuteAsync(
                    "UPDATE dbo.USERS SET MFASecret = @Secret WHERE USER_ID = @Id;",
                    new { Secret = secret, Id = userId }
                );

                // Construct otpauth URI using configured issuer for compatibility.
                string issuer = string.IsNullOrWhiteSpace(_jwt.Issuer) ? "SPARC_API" : _jwt.Issuer;
                string uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(emailClaim)}"
                           + $"?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30";

                // Do not log the secret in resLog; only return to client.
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
        /// Step 2: Confirm a TOTP code; if valid, enable MFA for this user.
        /// </summary>
        [Authorize]
        [HttpPost("confirm")]
        public async Task<IActionResult> Confirm([FromBody] string code)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper
                .LogEndpointCallAsync(_db, "MfaController.Confirm", HttpContext.Request.Path);
            // Redact incoming code in the logs.
            string reqLog = JsonSerializer.Serialize(new { Code = "REDACTED" });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                // Extract user id from JWT.
                var subClaim = User.FindFirstValue(ClaimTypes.NameIdentifier)
                             ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                if (string.IsNullOrEmpty(subClaim)
                 || !int.TryParse(subClaim, out var userId))
                {
                    statusCode = 401;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid token claims." });
                    return Unauthorized(new { error = "Invalid token claims." });
                }

                // Retrieve stored secret and validate the code.
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

                var totp = new Totp(Base32Encoding.ToBytes(secret));
                if (!totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay))
                {
                    statusCode = 400;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid MFA code." });
                    return BadRequest(new { error = "Invalid MFA code." });
                }

                // Flip the IsMfaEnabled flag.
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
