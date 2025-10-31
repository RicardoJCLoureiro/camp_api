// Controllers/AuthController.cs
//
// Purpose
//   Authentication + MFA + session refresh using a cookie-based JWT flow.
//   - Login issues an HttpOnly "accessToken" cookie after credential checks
//   - MFA (TOTP) is supported (setup/verify/login-with-mfa)
//   - Token refresh rotates the JWT while keeping the same cookie transport
//   - Forgot/Reset password flows with e-mail & MFA confirmation
//
// Notes
//   - ✅ Roles are NOW embedded as role claims in the JWT token at issuance
//     (ClaimTypes.Role for each role). This enables [Authorize(Roles="...")]
//     and User.IsInRole("...") across your controllers.
//   - We also include ClaimTypes.NameIdentifier in addition to "sub" for
//     compatibility with code that reads either.
//   - Login currently mints a JWT cookie before the MFA branching. That’s the
//     existing behavior; we keep it intact, just with roles included.
//
// Security
//   - Cookie: HttpOnly, Secure, SameSite=None for cross-site frontend if needed.
//   - Passwords arrive hashed from the frontend and compared hash-to-hash.
//   - All time values are UTC.
//
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using QRCoder;
using SPARC_API.DTOs;
using SPARC_API.Helpers;
using SPARC_API.Models;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SPARC_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("DefaultPolicy")]
    public class AuthController : ControllerBase
    {
        private readonly IDbConnection _db;
        private readonly JwtSettings _jwt;
        private readonly ILogger<AuthController> _logger;
        private readonly EmailService _emailService;
        private readonly IConfiguration _config;

        public AuthController(
            IDbConnection db,
            IOptions<JwtSettings> jwtOptions,
            ILogger<AuthController> logger,
            EmailService emailService,
            IConfiguration configuration)
        {
            _db = db;
            _jwt = jwtOptions.Value;
            _logger = logger;
            _emailService = emailService;
            _config = configuration;
        }

        // Writes the JWT to an HttpOnly cookie named "accessToken".
        private void AppendJwtCookie(string token, DateTime expires)
        {
            Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = expires,
                Path = "/"
            });
        }

        // Query active role names for a user. Distinct + ordered for stability.
        private async Task<List<string>> GetUserRolesAsync(int userId)
        {
            var roles = (await _db.QueryAsync<string>(@"
        SELECT DISTINCT r.ROLE_NAME
        FROM dbo.USER_ROLES ur
        INNER JOIN dbo.ROLES r ON r.ROLE_ID = ur.ROLE_ID
        WHERE ur.USER_ID = @UserId
          AND r.IS_ACTIVE = 1
        ORDER BY r.ROLE_NAME;",
                new { UserId = userId }
            )).ToList();

            return roles;
        }

        // Combines USERS row with the roles list to build the client session model.
        private async Task<UserSession> BuildUserSessionAsync(int userId)
        {
            var user = await _db.QueryFirstAsync<dynamic>(@"
                SELECT USER_ID AS UserId,
                       EMAIL   AS Email,
                       NAME    AS Name,
                       SURNAME AS Surname,
                       PROFILE_PICTURE_URL AS ProfilePictureUrl
                FROM dbo.USERS
                WHERE USER_ID = @UserId;", new { UserId = userId });

            var roles = await GetUserRolesAsync(userId);

            return new UserSession
            {
                UserId = (int)user.UserId,
                Email = (string)user.Email,
                Name = $"{(string)user.Name} {(string)user.Surname}".Trim(),
                ProfilePictureUrl = (string?)user.ProfilePictureUrl,
                Roles = roles
            };
        }

        // Builds a JWT that includes sub/email/jti + NameIdentifier + Role claims.
        private string BuildJwtWithRoles(int userId, string email, IEnumerable<string> roles, out DateTime expires)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var now = DateTime.UtcNow;
            expires = now.AddMinutes(_jwt.ExpireMinutes);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(ClaimTypes.Email, email),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var role in roles ?? Enumerable.Empty<string>())
                claims.Add(new Claim(ClaimTypes.Role, role));

            var token = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                notBefore: now,
                expires: expires,
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // POST /api/auth/login
        // Flow:
        //   1) Validate email + passwordHash (already hashed by frontend).
        //   2) Mint a JWT cookie (now WITH roles).
        //   3) If MFA is enabled:
        //        - If secret missing → return { mfaSetupRequired: true }
        //        - If secret present  → return { mfaRequired: true }
        //   4) If MFA disabled: return session + expiry.
        [HttpPost("login")]
        [EnableRateLimiting("LoginPolicy")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, "AuthController.Login", HttpContext.Request.Path);
            string reqLog = JsonSerializer.Serialize(new { dto.Email, password = "REDACTED" });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var user = await _db.QueryFirstOrDefaultAsync<dynamic>(@"
                    SELECT USER_ID       AS UserID,
                           EMAIL         AS UserEmail,
                           NAME + ' ' + SURNAME AS UserName,
                           PROFILE_PICTURE_URL  AS ProfilePictureUrl,
                           PASSWORD_HASH AS PasswordHash,
                           MFASecret,
                           IsMfaEnabled
                    FROM dbo.USERS
                    WHERE EMAIL = @Email AND IS_ACTIVE = 1;", new { dto.Email });

                if (user == null || user.PasswordHash != dto.Password)
                {
                    statusCode = 401;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid credentials." });
                    return Unauthorized(new { error = "Invalid credentials." });
                }

                // JWT with roles (even before MFA branching, preserving existing behavior)
                var roles = await GetUserRolesAsync((int)user.UserID);
                var jwtToken = BuildJwtWithRoles((int)user.UserID, (string)user.UserEmail, roles, out var expires);
                AppendJwtCookie(jwtToken, expires);

                bool isMfaEnabled = (bool)user.IsMfaEnabled;
                bool hasSecret = !string.IsNullOrEmpty((string)user.MFASecret);

                if (isMfaEnabled && !hasSecret)
                {
                    resLog = JsonSerializer.Serialize(new { mfaSetupRequired = true });
                    return Ok(new { mfaSetupRequired = true });
                }
                if (isMfaEnabled && hasSecret)
                {
                    resLog = JsonSerializer.Serialize(new { mfaRequired = true });
                    return Ok(new { mfaRequired = true });
                }

                // Non-MFA flow: return user (with roles) + expiry
                var session = await BuildUserSessionAsync((int)user.UserID);
                if (session.Roles is null || !session.Roles.Any())
                {
                    statusCode = 400;
                    resLog = JsonSerializer.Serialize(new { error = "noRoles" });
                    return BadRequest(new { error = "noRoles" });
                }

                resLog = JsonSerializer.Serialize(new { user = new { session.UserId, session.Email }, expires });
                return Ok(new { user = session, expires });
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
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/mfa/login
        // Validates TOTP for users with MFA enabled and issues a fresh JWT cookie (with roles).
        [HttpPost("mfa/login")]
        [EnableRateLimiting("LoginPolicy")]
        public async Task<IActionResult> LoginWithMfa([FromBody] LoginWithMfaDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.LoginWithMfa", HttpContext.Request.Path);
            string reqLog = JsonSerializer.Serialize(new { dto.Email, Code = "REDACTED" });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var user = await _db.QueryFirstOrDefaultAsync<dynamic>(@"
                    SELECT USER_ID       AS UserID,
                           EMAIL         AS UserEmail,
                           PASSWORD_HASH AS PasswordHash,
                           MFASecret     AS MfaSecret,
                           IsMfaEnabled
                    FROM dbo.USERS
                    WHERE EMAIL = @Email AND IS_ACTIVE = 1;", new { dto.Email });

                if (user == null || user.PasswordHash != dto.Password || !(bool)user.IsMfaEnabled)
                {
                    statusCode = 401;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid credentials or MFA not enabled." });
                    return Unauthorized(new { error = "Invalid credentials or MFA not enabled." });
                }

                // TOTP verification
                var secretBytes = Base32Encoding.ToBytes((string)user.MfaSecret!);
                var totp = new Totp(secretBytes);
                if (!totp.VerifyTotp(dto.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay))
                {
                    statusCode = 401;
                    resLog = JsonSerializer.Serialize(new { error = "Invalid MFA code." });
                    return Unauthorized(new { error = "Invalid MFA code." });
                }

                // Issue JWT with roles after MFA passes
                var roles = await GetUserRolesAsync((int)user.UserID);
                var jwtToken = BuildJwtWithRoles((int)user.UserID, (string)user.UserEmail, roles, out var expires);
                AppendJwtCookie(jwtToken, expires);

                var session = await BuildUserSessionAsync((int)user.UserID);
                resLog = JsonSerializer.Serialize(new { user = new { session.UserId, session.Email }, expires });
                return Ok(new { user = session, expires });
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/mfa/setup  (requires existing JWT)
        [Authorize]
        [HttpPost("mfa/setup")]
        public async Task<IActionResult> SetupMfa()
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.SetupMfa", HttpContext.Request.Path);
            string reqLog = "{}";
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                var emailClaim = User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue(JwtRegisteredClaimNames.Email);
                if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId) || string.IsNullOrEmpty(emailClaim))
                    return Unauthorized(new { error = "Invalid or missing claims." });

                byte[] secretBytes = KeyGeneration.GenerateRandomKey(20);
                string base32Secret = Base32Encoding.ToString(secretBytes);
                await _db.ExecuteAsync("UPDATE dbo.USERS SET MFASecret = @secret WHERE USER_ID = @id", new { secret = base32Secret, id = userId });

                string issuer = _jwt.Issuer;
                string label = $"{WebUtility.UrlEncode(issuer)}:{WebUtility.UrlEncode(emailClaim)}";
                string parameters = $"secret={base32Secret}&issuer={WebUtility.UrlEncode(issuer)}&digits=6&period=30";
                string otpAuthUri = $"otpauth://totp/{label}?{parameters}";
                using var qrGen = new QRCodeGenerator();
                using var qrData = qrGen.CreateQrCode(otpAuthUri, QRCoder.QRCodeGenerator.ECCLevel.Q);
                using var png = new PngByteQRCode(qrData);
                string qrBase64 = Convert.ToBase64String(png.GetGraphic(20));

                var response = new MfaSetupResponseDto { QrCodeImage = $"data:image/png;base64,{qrBase64}", ManualEntryKey = base32Secret };
                resLog = JsonSerializer.Serialize(new { issued = true });
                return Ok(response);
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/mfa/verify  (requires existing JWT)
        [Authorize]
        [HttpPost("mfa/verify")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.VerifyMfa", HttpContext.Request.Path);
            string reqLog = JsonSerializer.Serialize(new { Code = "REDACTED" });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                if (string.IsNullOrEmpty(userIdClaim) || !int.TryParse(userIdClaim, out var userId))
                    return Unauthorized(new { error = "Invalid or missing user ID in token." });

                var secret = await _db.QueryFirstOrDefaultAsync<string?>(@"SELECT MFASecret FROM dbo.USERS WHERE USER_ID = @id", new { id = userId });
                if (string.IsNullOrEmpty(secret))
                    return BadRequest(new { error = "MFA not initialized." });

                var totp = new Totp(Base32Encoding.ToBytes(secret));
                if (!totp.VerifyTotp(dto.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay))
                    return BadRequest(new { error = "Invalid MFA code." });

                await _db.ExecuteAsync(@"UPDATE dbo.USERS SET IsMfaEnabled = 1 WHERE USER_ID = @id", new { id = userId });

                resLog = JsonSerializer.Serialize(new { success = true });
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/refresh  (requires existing JWT)
        // Rotates the JWT cookie (new expiry/jti) and returns fresh session data.
        [Authorize]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.Refresh", HttpContext.Request.Path);
            string reqLog = "{}";
            string resLog = "";
            int status = 200;
            string? error = null;

            try
            {
                var subClaim = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                var emailClaim = User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue(JwtRegisteredClaimNames.Email);

                if (string.IsNullOrEmpty(subClaim) || !int.TryParse(subClaim, out var userId) || string.IsNullOrEmpty(emailClaim))
                    return Unauthorized(new { error = "Invalid token claims." });

                var exists = await _db.ExecuteScalarAsync<int>(@"
                    SELECT COUNT(1) FROM dbo.USERS
                    WHERE USER_ID = @UserId AND EMAIL = @Email AND IS_ACTIVE = 1;",
                    new { UserId = userId, Email = emailClaim });

                if (exists == 0)
                    return Unauthorized(new { error = "User no longer active." });

                // Re-embed current roles in the refreshed token
                var roles = await GetUserRolesAsync(userId);
                var token = BuildJwtWithRoles(userId, emailClaim, roles, out var expires);

                AppendJwtCookie(token, expires);

                var session = await BuildUserSessionAsync(userId);

                resLog = JsonSerializer.Serialize(new { expires });
                return Ok(new { user = session, expires });
            }
            catch (Exception ex)
            {
                status = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // GET /api/auth/refresh-contexts  (requires existing JWT)
        // Returns current session only (no token rotation).
        [Authorize]
        [HttpGet("refresh-contexts")]
        public async Task<IActionResult> RefreshContexts()
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.RefreshContexts", HttpContext.Request.Path);
            string reqLog = "{}";
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var subClaim = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(JwtRegisteredClaimNames.Sub);
                var emailClaim = User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue(JwtRegisteredClaimNames.Email);

                if (string.IsNullOrEmpty(subClaim) || !int.TryParse(subClaim, out var userId) || string.IsNullOrEmpty(emailClaim))
                    return Unauthorized(new { error = "Invalid token claims." });

                var exists = await _db.ExecuteScalarAsync<int>(@"
                    SELECT COUNT(1) FROM dbo.USERS
                    WHERE USER_ID = @UserId AND EMAIL = @Email AND IS_ACTIVE = 1;",
                    new { UserId = userId, Email = emailClaim });

                if (exists == 0)
                    return Unauthorized(new { error = "userInactive" });

                var session = await BuildUserSessionAsync(userId);

                resLog = JsonSerializer.Serialize(new { rolesCount = session.Roles.Count() });
                return Ok(new { user = session });
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/logout
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.Logout", HttpContext.Request.Path);
            string reqLog = "{}";
            string resLog = "";
            int statusCode = 204;
            string? error = null;

            try
            {
                Response.Cookies.Append("accessToken", "", new CookieOptions
                {
                    Expires = DateTime.UtcNow.AddDays(-1),
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Path = "/"
                });

                resLog = JsonSerializer.Serialize(new { message = "loggedOut" });
                return NoContent();
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/forgotpassword
        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.ForgotPassword", HttpContext.Request.Path);
            string reqLog = JsonSerializer.Serialize(new { dto.Email, dto.Language });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var user = await _db.QueryFirstOrDefaultAsync<dynamic>(@"
                    SELECT USER_ID AS UserID, EMAIL AS UserEmail, NAME + ' ' + SURNAME AS UserName
                    FROM dbo.USERS
                    WHERE EMAIL = @Email AND IS_ACTIVE = 1;", new { dto.Email });

                if (user == null)
                    return BadRequest(new { message = "emailNotFound" });

                string token = Guid.NewGuid().ToString("N");
                DateTime exp = DateTime.UtcNow.AddHours(1);
                await _db.ExecuteAsync(@"
                    INSERT INTO PASSWORD_RESET_REQUESTS (USER_ID, RESET_TOKEN, EXPIRES_AT)
                    VALUES (@UserID, @Token, @ExpiresAt);",
                    new { UserID = user.UserID, Token = token, ExpiresAt = exp });

                var baseUrl = _config["Frontend:ResetPasswordUrl"]?.TrimEnd('/')
                              ?? throw new InvalidOperationException("Missing Frontend:ResetPasswordUrl");
                var resetLink = $"{baseUrl}?token={Uri.EscapeDataString(token)}&lang={Uri.EscapeDataString(dto.Language ?? "en")}";

                await _emailService.SendResetPasswordEmailAsync(user.UserEmail, dto.Language, user.UserName, resetLink);

                resLog = JsonSerializer.Serialize(new { message = "resetEmailSent" });
                return Ok(new { message = "resetEmailSent" });
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // POST /api/auth/resetpassword
        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(_db, "AuthController.ResetPassword", HttpContext.Request.Path);
            string reqLog = JsonSerializer.Serialize(new { dto.Token, dto.Code });
            string resLog = "";
            int statusCode = 200;
            string? error = null;

            try
            {
                var req = await _db.QueryFirstOrDefaultAsync<dynamic>(@"
                    SELECT REQUEST_ID, USER_ID, IS_USED, EXPIRES_AT
                    FROM dbo.PASSWORD_RESET_REQUESTS
                    WHERE RESET_TOKEN = @Token;", new { dto.Token });

                if (req == null || req.IS_USED || req.EXPIRES_AT < DateTime.UtcNow)
                    return BadRequest(new { error = "invalidOrExpiredToken" });

                int userId = req.USER_ID;

                var mfaSecret = await _db.QueryFirstOrDefaultAsync<string?>(@"
                    SELECT MFASecret FROM dbo.USERS WHERE USER_ID = @Id;", new { Id = userId });

                if (string.IsNullOrEmpty(mfaSecret))
                    return BadRequest(new { error = "mfaNotSetup" });

                var totp = new Totp(Base32Encoding.ToBytes(mfaSecret));
                if (!totp.VerifyTotp(dto.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay))
                    return BadRequest(new { error = "invalidMfaCode" });

                await _db.ExecuteAsync(@"
                    UPDATE dbo.USERS SET PASSWORD_HASH = @Hash WHERE USER_ID = @Id;",
                    new { Hash = dto.NewPassword, Id = userId });

                await _db.ExecuteAsync(@"
                    UPDATE dbo.PASSWORD_RESET_REQUESTS SET IS_USED = 1 WHERE REQUEST_ID = @ReqId;",
                    new { ReqId = req.REQUEST_ID });

                resLog = JsonSerializer.Serialize(new { success = true });
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                statusCode = 500; error = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(_db, endpointLogId, reqLog, resLog, statusCode, error, (int)sw.ElapsedMilliseconds);
            }
        }
    }
}
