// Controllers/UsersController.cs
using System;
using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SPARC_API.Helpers;
using SPARC_API.DTOs;     // PagedResult<T>, UsersListItemDto, UserDetailsDto, UpdateUserDetailsDto, ChangePasswordDto
using SPARC_API.Models;  // UserListRequestDto

namespace SPARC_API.Controllers
{
    // User management endpoints (list, self-details, self-update, change-password).
    // Entire controller is JWT-protected.
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UsersController : ControllerBase
    {
        private readonly IDbConnection _db;
        private const int MaxPageSize = 100;

        public UsersController(IDbConnection db) => _db = db;

        // ──────────────────────────────────────────────────────────────
        // POST /api/users/list
        // Returns paginated user list.
        // Superuser (id=1) sees all; others do not see superuser record.
        [HttpPost("list")]
        public async Task<IActionResult> List([FromBody] UserListRequestDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, nameof(UsersController.List), HttpContext.Request.Path + Request.QueryString);
            string reqLog = JsonSerializer.Serialize(dto);
            string? resLog = null;
            string? errorInfo = null;
            int statusCode = 200;

            try
            {
                // Resolve caller id from JWT and detect superuser (id==1).
                var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (!int.TryParse(sub, out var callerId))
                    throw new UnauthorizedAccessException("Invalid token claims.");

                bool isSuper = callerId == 1;

                int page = Math.Max(dto.Page, 1);
                int pageSize = Math.Clamp(dto.PageSize, 1, MaxPageSize);
                int offset = (page - 1) * pageSize;

                // Filter hides superuser from non-super callers.
                string where = isSuper ? "1=1" : "u.USER_ID <> 1";

                // Two queries in one round-trip: total count + page slice via ROW_NUMBER().
                string countSql = $@"
SELECT COUNT(*) AS TotalCount
  FROM dbo.USERS u
  LEFT JOIN dbo.USER_DETAILS ud ON ud.USER_ID = u.USER_ID
 WHERE {where};
";

                string pageSql = $@"
WITH Rows AS (
  SELECT
    ROW_NUMBER() OVER (ORDER BY u.NAME, u.SURNAME) AS RowNum,
    u.USER_ID              AS UserId,
    u.NAME                 AS Name,
    u.SURNAME              AS Surname,
    u.EMAIL                AS Email,
    u.LANGUAGE_PREFERENCE  AS LanguagePreference,
    u.PROFILE_PICTURE_URL  AS ProfilePictureUrl,
    u.IS_ACTIVE            AS IsActive,
    u.IsMfaEnabled         AS IsMfaEnabled,
    ud.BIRTH_DATE          AS BirthDate,
    ud.GENDER              AS Gender,
    ud.IDENTITY_NUMBER     AS IdentityNumber,
    ud.BLOOD_TYPE          AS BloodType,
    ud.ADDRESS_LINE_1      AS AddressLine1,
    ud.ADDRESS_LINE_2      AS AddressLine2,
    ud.CITY                AS City,
    ud.STATE_PROVINCE      AS StateProvince,
    ud.POSTAL_CODE         AS PostalCode,
    ud.COUNTRY             AS Country,
    ud.PHONE_NUMBER        AS PhoneNumber,
    ud.EMERGENCY_CONTACT_NAME         AS EmergencyContactName,
    ud.EMERGENCY_CONTACT_PHONE        AS EmergencyContactPhone,
    ud.EMERGENCY_CONTACT_RELATIONSHIP AS EmergencyContactRelationship,
    ud.ALLERGIES           AS Allergies,
    ud.MEDICAL_CONDITIONS  AS MedicalConditions,
    u.CREATED_BY           AS CreatedBy,
    u.CREATED_AT           AS CreatedAt,
    u.UPDATED_BY           AS UpdatedBy,
    u.UPDATED_AT           AS UpdatedAt
  FROM dbo.USERS u
  LEFT JOIN dbo.USER_DETAILS ud ON ud.USER_ID = u.USER_ID
  WHERE {where}
)
SELECT *
  FROM Rows
 WHERE RowNum BETWEEN @Offset + 1 AND @Offset + @PageSize;
";

                using var multi = await _db.QueryMultipleAsync(
                    countSql + pageSql,
                    new { Offset = offset, PageSize = pageSize }
                );

                int totalCount = multi.ReadFirst<int>();
                var items = multi.Read<UsersListItemDto>();

                var result = new PagedResult<UsersListItemDto>
                {
                    Items = items,
                    TotalCount = totalCount,
                    Page = page,
                    PageSize = pageSize
                };

                resLog = JsonSerializer.Serialize(new
                {
                    result.TotalCount,
                    result.Page,
                    result.PageSize
                });
                return Ok(result);
            }
            catch (UnauthorizedAccessException uaEx)
            {
                statusCode = 401;
                resLog = JsonSerializer.Serialize(new { error = uaEx.Message });
                return Unauthorized(new { error = uaEx.Message });
            }
            catch (Exception ex)
            {
                statusCode = 500;
                errorInfo = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(
                    _db, endpointLogId, reqLog, resLog, statusCode, errorInfo, (int)sw.ElapsedMilliseconds);
            }
        }

        // ──────────────────────────────────────────────────────────────
        // GET /api/users/me/details
        // Return the *caller’s* combined USERS + USER_DETAILS record.
        [HttpGet("me/details")]
        public async Task<IActionResult> GetMyDetails()
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, nameof(GetMyDetails), HttpContext.Request.Path + Request.QueryString);
            string reqLog = "{}";
            string? resLog = null;
            string? errorInfo = null;
            int statusCode = 200;

            try
            {
                var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (!int.TryParse(sub, out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                var sql = @"
SELECT
  u.USER_ID              AS UserId,
  u.NAME                 AS Name,
  u.SURNAME              AS Surname,
  u.EMAIL                AS Email,
  u.LANGUAGE_PREFERENCE  AS LanguagePreference,
  u.PROFILE_PICTURE_URL  AS ProfilePictureUrl,
  u.IS_ACTIVE            AS IsActive,
  u.IsMfaEnabled         AS IsMfaEnabled,
  ud.BIRTH_DATE          AS BirthDate,
  ud.GENDER              AS Gender,
  ud.IDENTITY_NUMBER     AS IdentityNumber,
  ud.BLOOD_TYPE          AS BloodType,
  ud.ADDRESS_LINE_1      AS AddressLine1,
  ud.ADDRESS_LINE_2      AS AddressLine2,
  ud.CITY                AS City,
  ud.STATE_PROVINCE      AS StateProvince,
  ud.POSTAL_CODE         AS PostalCode,
  ud.COUNTRY             AS Country,
  ud.PHONE_NUMBER        AS PhoneNumber,
  ud.EMERGENCY_CONTACT_NAME         AS EmergencyContactName,
  ud.EMERGENCY_CONTACT_PHONE        AS EmergencyContactPhone,
  ud.EMERGENCY_CONTACT_RELATIONSHIP AS EmergencyContactRelationship,
  ud.ALLERGIES           AS Allergies,
  ud.MEDICAL_CONDITIONS  AS MedicalConditions,
  u.CREATED_BY           AS CreatedBy,
  u.CREATED_AT           AS CreatedAt,
  u.UPDATED_BY           AS UpdatedBy,
  u.UPDATED_AT           AS UpdatedAt
FROM dbo.USERS u
LEFT JOIN dbo.USER_DETAILS ud ON ud.USER_ID = u.USER_ID
WHERE u.USER_ID = @UserId;";

                var dto = await _db.QueryFirstOrDefaultAsync<UserDetailsDto>(sql, new { UserId = userId });
                if (dto == null)
                {
                    statusCode = 404;
                    resLog = JsonSerializer.Serialize(new { error = "notFound" });
                    return NotFound(new { error = "notFound" });
                }

                resLog = JsonSerializer.Serialize(new { ok = true });
                return Ok(dto);
            }
            catch (Exception ex)
            {
                statusCode = 500;
                errorInfo = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(
                    _db, endpointLogId, reqLog, resLog, statusCode, errorInfo, (int)sw.ElapsedMilliseconds);
            }
        }

        // ──────────────────────────────────────────────────────────────
        // PATCH /api/users/me/details (partial update)
        // Upserts USER_DETAILS row on first write, updates USERS/USER_DETAILS selectively.
        [HttpPatch("me/details")]
        public async Task<IActionResult> PatchMyDetails([FromBody] UpdateUserDetailsDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, nameof(PatchMyDetails), HttpContext.Request.Path + Request.QueryString);
            string reqLog = JsonSerializer.Serialize(dto);
            string? resLog = null;
            string? errorInfo = null;
            int statusCode = 200;

            try
            {
                var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (!int.TryParse(sub, out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                // Dynamically builds SET clauses only for fields provided in DTO.
                var usersSet = new System.Collections.Generic.List<string>();
                var detailsSet = new System.Collections.Generic.List<string>();
                var p = new DynamicParameters();
                p.Add("UserId", userId);

                // USERS table surface
                if (dto.Name != null) { usersSet.Add("NAME = @Name"); p.Add("Name", dto.Name); }
                if (dto.Surname != null) { usersSet.Add("SURNAME = @Surname"); p.Add("Surname", dto.Surname); }
                if (dto.LanguagePreference != null) { usersSet.Add("LANGUAGE_PREFERENCE = @Lang"); p.Add("Lang", dto.LanguagePreference); }
                if (dto.ProfilePictureUrl != null) { usersSet.Add("PROFILE_PICTURE_URL = @Pic"); p.Add("Pic", dto.ProfilePictureUrl); }

                // USER_DETAILS surface
                if (dto.BirthDate.HasValue) { detailsSet.Add("BIRTH_DATE = @BirthDate"); p.Add("BirthDate", dto.BirthDate); }
                if (dto.Gender != null) { detailsSet.Add("GENDER = @Gender"); p.Add("Gender", dto.Gender); }
                if (dto.IdentityNumber != null) { detailsSet.Add("IDENTITY_NUMBER = @IdNumber"); p.Add("IdNumber", dto.IdentityNumber); }
                if (dto.BloodType != null) { detailsSet.Add("BLOOD_TYPE = @BloodType"); p.Add("BloodType", dto.BloodType); }
                if (dto.AddressLine1 != null) { detailsSet.Add("ADDRESS_LINE_1 = @Addr1"); p.Add("Addr1", dto.AddressLine1); }
                if (dto.AddressLine2 != null) { detailsSet.Add("ADDRESS_LINE_2 = @Addr2"); p.Add("Addr2", dto.AddressLine2); }
                if (dto.City != null) { detailsSet.Add("CITY = @City"); p.Add("City", dto.City); }
                if (dto.StateProvince != null) { detailsSet.Add("STATE_PROVINCE = @State"); p.Add("State", dto.StateProvince); }
                if (dto.PostalCode != null) { detailsSet.Add("POSTAL_CODE = @Postal"); p.Add("Postal", dto.PostalCode); }
                if (dto.Country != null) { detailsSet.Add("COUNTRY = @Country"); p.Add("Country", dto.Country); }
                if (dto.PhoneNumber != null) { detailsSet.Add("PHONE_NUMBER = @Phone"); p.Add("Phone", dto.PhoneNumber); }
                if (dto.EmergencyContactName != null) { detailsSet.Add("EMERGENCY_CONTACT_NAME = @EName"); p.Add("EName", dto.EmergencyContactName); }
                if (dto.EmergencyContactPhone != null) { detailsSet.Add("EMERGENCY_CONTACT_PHONE = @EPhone"); p.Add("EPhone", dto.EmergencyContactPhone); }
                if (dto.EmergencyContactRelationship != null) { detailsSet.Add("EMERGENCY_CONTACT_RELATIONSHIP = @ERel"); p.Add("ERel", dto.EmergencyContactRelationship); }
                if (dto.Allergies != null) { detailsSet.Add("ALLERGIES = @Allergies"); p.Add("Allergies", dto.Allergies); }
                if (dto.MedicalConditions != null) { detailsSet.Add("MEDICAL_CONDITIONS = @Med"); p.Add("Med", dto.MedicalConditions); }

                if (!usersSet.Any() && !detailsSet.Any())
                {
                    statusCode = 400;
                    resLog = JsonSerializer.Serialize(new { error = "noChanges" });
                    return BadRequest(new { error = "noChanges" });
                }

                // Ensure USER_DETAILS row exists before attempting update.
                await _db.ExecuteAsync(@"
IF NOT EXISTS (SELECT 1 FROM dbo.USER_DETAILS WHERE USER_ID = @UserId)
    INSERT INTO dbo.USER_DETAILS (USER_ID) VALUES (@UserId);", new { UserId = userId });

                if (usersSet.Any())
                {
                    var sqlUsers = $"UPDATE dbo.USERS SET {string.Join(", ", usersSet)}, UPDATED_AT = GETDATE() WHERE USER_ID = @UserId;";
                    await _db.ExecuteAsync(sqlUsers, p);
                }
                if (detailsSet.Any())
                {
                    var sqlDetails = $"UPDATE dbo.USER_DETAILS SET {string.Join(", ", detailsSet)} WHERE USER_ID = @UserId;";
                    await _db.ExecuteAsync(sqlDetails, p);
                }

                resLog = JsonSerializer.Serialize(new { updated = true });
                return Ok(new { updated = true });
            }
            catch (Exception ex)
            {
                statusCode = 500;
                errorInfo = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(
                    _db, endpointLogId, reqLog, resLog, statusCode, errorInfo, (int)sw.ElapsedMilliseconds);
            }
        }

        // ──────────────────────────────────────────────────────────────
        // POST /api/users/me/change-password
        // Compares current password hash with DB; if matches, persists new hash.
        [HttpPost("me/change-password")]
        public async Task<IActionResult> ChangeMyPassword([FromBody] ChangePasswordDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, nameof(ChangeMyPassword), HttpContext.Request.Path + Request.QueryString);
            string reqLog = "{\"pwd\":\"REDACTED\"}";
            string? resLog = null;
            string? errorInfo = null;
            int statusCode = 200;

            try
            {
                var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                if (!int.TryParse(sub, out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                var currentHash = await _db.ExecuteScalarAsync<string?>(
                    "SELECT PASSWORD_HASH FROM dbo.USERS WHERE USER_ID = @UserId AND IS_ACTIVE = 1;",
                    new { UserId = userId });

                if (currentHash == null || !string.Equals(currentHash, dto.CurrentPasswordHash, StringComparison.Ordinal))
                {
                    statusCode = 400;
                    resLog = JsonSerializer.Serialize(new { error = "invalidCurrentPassword" });
                    return BadRequest(new { error = "invalidCurrentPassword" });
                }

                await _db.ExecuteAsync(@"
UPDATE dbo.USERS
   SET PASSWORD_HASH = @NewHash,
       UPDATED_AT = GETDATE()
 WHERE USER_ID = @UserId;",
                    new { NewHash = dto.NewPasswordHash, UserId = userId });

                resLog = JsonSerializer.Serialize(new { changed = true });
                return Ok(new { changed = true });
            }
            catch (Exception ex)
            {
                statusCode = 500;
                errorInfo = ex.ToString();
                resLog = JsonSerializer.Serialize(new { error = "Internal server error." });
                return StatusCode(500, new { error = "Internal server error." });
            }
            finally
            {
                sw.Stop();
                await LoggingHelper.LogRequestResponseAsync(
                    _db, endpointLogId, reqLog, resLog, statusCode, errorInfo, (int)sw.ElapsedMilliseconds);
            }
        }
    }
}
