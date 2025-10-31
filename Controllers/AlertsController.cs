using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SPARC_API.DTOs;
using SPARC_API.Helpers;

namespace SPARC_API.Controllers
{
    // Alerts API: summary, paging, read/unread, archive/unarchive, bulk ops.
    // Requires a valid JWT (roles embedded by AuthController).
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class AlertsController : ControllerBase
    {
        private readonly IDbConnection _db;
        private const int MaxPageSize = 100;
        private const int DefaultSummaryTake = 6;
        private const int MaxSummaryTake = 50;
        private const int BodyPreviewLen = 200;

        public AlertsController(IDbConnection db) => _db = db;

        // ───────────────────────────── helpers ─────────────────────────────

        // Extracts user id from JWT ("sub" or ClaimTypes.NameIdentifier).
        private bool TryGetUserId(out int userId)
        {
            var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            return int.TryParse(sub, out userId);
        }

        // Builds WHERE fragment for status. Matches "active" semantics:
        // active = not archived AND (no expiry OR future expiry)
        private static string StatusWhere(string? status)
        {
            var s = (status ?? "active").Trim().ToLowerInvariant();
            return s switch
            {
                "archived" => "ua.ARCHIVED_AT IS NOT NULL",
                "all" => "1=1",
                _ => "ua.ARCHIVED_AT IS NULL AND (ua.EXPIRES_AT IS NULL OR ua.EXPIRES_AT > SYSUTCDATETIME())"
            };
        }

        // Create an ETag from a simple fingerprint (e.g., unreadCount + newest ticks).
        private static string MakeEtag(string fingerprint)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(fingerprint));
            var b64 = Convert.ToBase64String(hash);
            return $"\"{b64}\""; // ETag must be quoted
        }

        // ──────────────────────────── GET /summary ────────────────────────────
        // Returns unread count + latest items (cap via ?max=).
        // Adds ETag support: If client sends If-None-Match matching current fingerprint, returns 304.
        [HttpGet("summary")]
        public async Task<IActionResult> GetSummary([FromQuery] int? max = null)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_SUMMARY", HttpContext.Request.Path + Request.QueryString);
            var reqLog = JsonSerializer.Serialize(new { max });
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                var take = Math.Clamp(max ?? DefaultSummaryTake, 1, MaxSummaryTake);

                var sql = @"
-- unread count (uses computed column IS_READ)
SELECT COUNT_BIG(1)
FROM dbo.USER_ALERTS
WHERE USER_ID = @UserId
  AND ARCHIVED_AT IS NULL
  AND IS_READ = 0
  AND (EXPIRES_AT IS NULL OR EXPIRES_AT > SYSUTCDATETIME());

-- latest items (short body preview only)
SELECT TOP (@Take)
       ua.ALERT_ID     AS Id,
       ua.TITLE        AS Title,
       ua.CREATED_AT   AS CreatedAtUtc,
       ua.READ_AT      AS ReadAt,
       ua.ARCHIVED_AT  AS ArchivedAt,
       ua.EXPIRES_AT   AS ExpiresAt,
       CAST(ua.IS_READ AS bit) AS IsRead,        -- ensure bool-friendly
       ua.SEVERITY_ID  AS SeverityId,
       s.CODE          AS SeverityCode,
       s.NAME          AS SeverityName,
       s.RANK_VALUE    AS SeverityRank,
       s.COLOR_HEX     AS ColorHex,
       ua.SOURCE       AS Source,
       ua.SOURCE_REF   AS SourceRef,
       LEFT(ua.BODY, @BodyPreviewLen) AS Body
FROM dbo.USER_ALERTS ua
INNER JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE ua.USER_ID = @UserId
  AND ua.ARCHIVED_AT IS NULL
  AND (ua.EXPIRES_AT IS NULL OR ua.EXPIRES_AT > SYSUTCDATETIME())
ORDER BY ua.CREATED_AT DESC, ua.ALERT_ID DESC;";

                using var multi = await _db.QueryMultipleAsync(sql, new
                {
                    UserId = userId,
                    Take = take,
                    BodyPreviewLen = BodyPreviewLen
                });

                long unread = await multi.ReadFirstAsync<long>();
                var rows = (await multi.ReadAsync()).ToList();

                var items = rows.Select(r => new AlertListItemDto
                {
                    Id = (long)r.Id,
                    Title = (string)r.Title,
                    Body = (string?)r.Body, // preview (<= 200)
                    CreatedAt = (DateTime)r.CreatedAtUtc,
                    ReadAt = (DateTime?)r.ReadAt,
                    ArchivedAt = (DateTime?)r.ArchivedAt,
                    ExpiresAt = (DateTime?)r.ExpiresAt,
                    Read = (bool)r.IsRead,
                    SeverityId = (int)r.SeverityId,
                    Severity = (string)r.SeverityCode,
                    SeverityName = (string)r.SeverityName,
                    SeverityRank = (int)r.SeverityRank,
                    ColorHex = (string?)r.ColorHex,
                    Source = (string?)r.Source,
                    SourceRef = (string?)r.SourceRef
                }).ToList();

                // ETag fingerprint: unread + newest createdAt ticks (or 0) + page size cap
                var newest = items.Count > 0 ? items[0].CreatedAt.Ticks : 0L;
                var etag = MakeEtag($"{unread}:{newest}:{take}");
                var ifNone = Request.Headers.IfNoneMatch.FirstOrDefault();
                if (!string.IsNullOrEmpty(ifNone) && string.Equals(ifNone, etag, StringComparison.Ordinal))
                {
                    Response.Headers.ETag = etag;
                    status = 304;
                    resLog = "{\"notModified\":true}";
                    return StatusCode(StatusCodes.Status304NotModified);
                }

                Response.Headers.ETag = etag;

                var payload = new AlertsSummaryDto { UnreadCount = (int)unread, Items = items };
                resLog = JsonSerializer.Serialize(new { unread, items = items.Count });
                return Ok(payload);
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ───────────────────────────── GET / (paged) ───────────────────────────
        // Filters: status, severity, text search, read-state; supports page/pageSize.
        [HttpGet]
        public async Task<IActionResult> List([FromQuery] AlertsListRequestDto q)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_LIST", HttpContext.Request.Path + Request.QueryString);
            var reqLog = JsonSerializer.Serialize(q);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var currentUserId))
                    return Unauthorized(new { error = "Invalid token claims." });

                // Role-based cross-user access:
                // - Same user can query self
                // - Admins can query any user
                var targetUserId = q.UserId ?? currentUserId;
                if (q.UserId.HasValue && q.UserId.Value != currentUserId && !User.IsInRole("Admin"))
                    return Forbid();

                // Mutually exclusive read-state filters
                if (q.OnlyUnread == true && q.OnlyRead == true)
                    return BadRequest(new { error = "Choose only one of: onlyUnread or onlyRead." });

                int page = Math.Max(q.Page, 1);
                int pageSize = Math.Clamp(q.PageSize, 1, MaxPageSize);
                int offset = (page - 1) * pageSize;

                // WHERE builder
                var sbWhere = new StringBuilder("ua.USER_ID = @UserId");
                sbWhere.Append(" AND " + StatusWhere(q.Status));
                if (q.OnlyUnread == true) sbWhere.Append(" AND ua.IS_READ = 0");
                else if (q.OnlyRead == true) sbWhere.Append(" AND ua.IS_READ = 1");
                if (!string.IsNullOrWhiteSpace(q.Severity)) sbWhere.Append(" AND s.CODE = @Severity");
                if (!string.IsNullOrWhiteSpace(q.Search)) sbWhere.Append(" AND (ua.TITLE LIKE @Search OR ua.BODY LIKE @Search)");

                var sql = $@"
-- total count
SELECT COUNT_BIG(1)
FROM dbo.USER_ALERTS ua
INNER JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE {sbWhere};

-- page slice (short body preview for list UX)
SELECT 
    ua.ALERT_ID     AS Id,
    ua.TITLE        AS Title,
    LEFT(ua.BODY, @BodyPreviewLen) AS Body,
    ua.CREATED_AT   AS CreatedAtUtc,
    ua.READ_AT      AS ReadAt,
    ua.ARCHIVED_AT  AS ArchivedAt,
    ua.EXPIRES_AT   AS ExpiresAt,
    CAST(ua.IS_READ AS bit) AS IsRead,           -- ensure bool-friendly
    ua.SEVERITY_ID  AS SeverityId,
    s.CODE          AS SeverityCode,
    s.NAME          AS SeverityName,
    s.RANK_VALUE    AS SeverityRank,
    s.COLOR_HEX     AS ColorHex,
    ua.SOURCE       AS Source,
    ua.SOURCE_REF   AS SourceRef
FROM dbo.USER_ALERTS ua
INNER JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE {sbWhere}
ORDER BY ua.CREATED_AT DESC, ua.ALERT_ID DESC
OFFSET @Offset ROWS FETCH NEXT @PageSize ROWS ONLY;";

                var args = new
                {
                    UserId = targetUserId,
                    Severity = string.IsNullOrWhiteSpace(q.Severity) ? null : q.Severity.Trim().ToLowerInvariant(),
                    Search = string.IsNullOrWhiteSpace(q.Search) ? null : $"%{q.Search.Trim()}%",
                    Offset = offset,
                    PageSize = pageSize,
                    BodyPreviewLen = BodyPreviewLen
                };

                using var multi = await _db.QueryMultipleAsync(sql, args);
                long total = await multi.ReadFirstAsync<long>();
                var rows = (await multi.ReadAsync()).ToList();

                var items = rows.Select(r => new AlertListItemDto
                {
                    Id = (long)r.Id,
                    Title = (string)r.Title,
                    Body = (string?)r.Body, // preview
                    CreatedAt = (DateTime)r.CreatedAtUtc,
                    ReadAt = (DateTime?)r.ReadAt,
                    ArchivedAt = (DateTime?)r.ArchivedAt,
                    ExpiresAt = (DateTime?)r.ExpiresAt,
                    Read = (bool)r.IsRead,
                    SeverityId = (int)r.SeverityId,
                    Severity = (string)r.SeverityCode,
                    SeverityName = (string)r.SeverityName,
                    SeverityRank = (int)r.SeverityRank,
                    ColorHex = (string?)r.ColorHex,
                    Source = (string?)r.Source,
                    SourceRef = (string?)r.SourceRef
                }).ToList();

                resLog = JsonSerializer.Serialize(new { total, count = items.Count, page, pageSize });
                // Return totalCount as long to avoid overflow risk
                return Ok(new { items, page, pageSize, totalCount = total });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ───────────────────────────── GET /{id} (full) ────────────────────────
        // Returns one full alert (with severity info) scoped to the current user.
        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetById([FromRoute] int id)
        {
            if (!TryGetUserId(out var userId))
                return Unauthorized(new { error = "Invalid token claims." });

            var sql = @"
SELECT 
    ua.ALERT_ID      AS AlertId,
    s.CODE           AS SeverityCode,
    s.NAME           AS SeverityName,
    s.RANK_VALUE     AS SeverityRank,
    s.COLOR_HEX      AS ColorHex,
    ua.TITLE         AS Title,
    ua.BODY          AS Body,
    ua.SOURCE        AS Source,
    ua.SOURCE_REF    AS SourceRef,
    ua.CREATED_AT    AS CreatedAt,
    ua.READ_AT       AS ReadAt,
    ua.ARCHIVED_AT   AS ArchivedAt,
    ua.EXPIRES_AT    AS ExpiresAt,
    CAST(ua.IS_READ AS bit) AS IsRead          -- ensure bool-friendly
FROM dbo.USER_ALERTS ua
INNER JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE ua.ALERT_ID = @Id AND ua.USER_ID = @UserId;";

            var row = await _db.QueryFirstOrDefaultAsync(sql, new { Id = id, UserId = userId });
            if (row == null) return NotFound();

            var dto = new AlertDto
            {
                AlertId = (int)row.AlertId,
                SeverityCode = (string)row.SeverityCode,
                SeverityName = (string)row.SeverityName,
                SeverityRank = (int)row.SeverityRank,
                ColorHex = (string?)row.ColorHex,
                Title = (string)row.Title,
                Body = (string?)row.Body,
                Source = (string?)row.Source,
                SourceRef = (string?)row.SourceRef,
                CreatedAt = (DateTime)row.CreatedAt,
                ReadAt = (DateTime?)row.ReadAt,
                ArchivedAt = (DateTime?)row.ArchivedAt,
                ExpiresAt = (DateTime?)row.ExpiresAt,
                IsRead = (bool)row.IsRead
            };

            return Ok(dto);
        }

        // ───────────────────────────── POST /mark-read ─────────────────────────
        [HttpPost("mark-read")]
        public async Task<IActionResult> MarkRead([FromBody] AlertsMarkRequestDto dto)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_MARK_READ", HttpContext.Request.Path);
            var reqLog = JsonSerializer.Serialize(dto);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                if (dto.Ids == null || dto.Ids.Length == 0)
                    return BadRequest(new { error = "No ids provided." });

                var sql = @"
UPDATE dbo.USER_ALERTS
SET READ_AT = SYSUTCDATETIME()
WHERE USER_ID = @UserId AND ALERT_ID IN @Ids AND IS_READ = 0;";

                var updated = await _db.ExecuteAsync(sql, new { UserId = userId, Ids = dto.Ids });
                resLog = JsonSerializer.Serialize(new { updated });
                if (updated == 0) return NoContent();
                return Ok(new { updated });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ──────────────────────────── POST /mark-unread ────────────────────────
        [HttpPost("mark-unread")]
        public async Task<IActionResult> MarkUnread([FromBody] AlertsMarkRequestDto dto)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_MARK_UNREAD", HttpContext.Request.Path);
            var reqLog = JsonSerializer.Serialize(dto);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                if (dto.Ids == null || dto.Ids.Length == 0)
                    return BadRequest(new { error = "No ids provided." });

                var sql = @"
UPDATE dbo.USER_ALERTS
SET READ_AT = NULL
WHERE USER_ID = @UserId AND ALERT_ID IN @Ids AND IS_READ = 1;";

                var updated = await _db.ExecuteAsync(sql, new { UserId = userId, Ids = dto.Ids });
                resLog = JsonSerializer.Serialize(new { updated });
                if (updated == 0) return NoContent();
                return Ok(new { updated });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ───────────────────────────── POST /archive ───────────────────────────
        [HttpPost("archive")]
        public async Task<IActionResult> Archive([FromBody] AlertsMarkRequestDto dto)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_ARCHIVE", HttpContext.Request.Path);
            var reqLog = JsonSerializer.Serialize(dto);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                if (dto.Ids == null || dto.Ids.Length == 0)
                    return BadRequest(new { error = "No ids provided." });

                var sql = @"
UPDATE dbo.USER_ALERTS
SET ARCHIVED_AT = SYSUTCDATETIME()
WHERE USER_ID = @UserId AND ALERT_ID IN @Ids AND ARCHIVED_AT IS NULL;";

                var updated = await _db.ExecuteAsync(sql, new { UserId = userId, Ids = dto.Ids });
                resLog = JsonSerializer.Serialize(new { updated });
                if (updated == 0) return NoContent();
                return Ok(new { updated });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ─────────────────────────── POST /unarchive ───────────────────────────
        [HttpPost("unarchive")]
        public async Task<IActionResult> Unarchive([FromBody] AlertsMarkRequestDto dto)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_UNARCHIVE", HttpContext.Request.Path);
            var reqLog = JsonSerializer.Serialize(dto);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                if (dto.Ids == null || dto.Ids.Length == 0)
                    return BadRequest(new { error = "No ids provided." });

                var sql = @"
UPDATE dbo.USER_ALERTS
SET ARCHIVED_AT = NULL
WHERE USER_ID = @UserId AND ALERT_ID IN @Ids AND ARCHIVED_AT IS NOT NULL;";

                var updated = await _db.ExecuteAsync(sql, new { UserId = userId, Ids = dto.Ids });
                resLog = JsonSerializer.Serialize(new { updated });
                if (updated == 0) return NoContent();
                return Ok(new { updated });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ────────────────────────── POST /mark-all-read ────────────────────────
        [HttpPost("mark-all-read")]
        public async Task<IActionResult> MarkAllRead([FromBody] ReadAllDto dto)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_MARK_ALL_READ", HttpContext.Request.Path);
            var reqLog = JsonSerializer.Serialize(dto);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                var sql = new StringBuilder(@"
UPDATE dbo.USER_ALERTS
SET READ_AT = SYSUTCDATETIME()
WHERE USER_ID = @UserId
  AND IS_READ = 0");

                if (dto?.Before is DateTime cutoff)
                    sql.Append(" AND CREATED_AT <= @Cutoff");

                var updated = await _db.ExecuteAsync(sql.ToString(), new { UserId = userId, Cutoff = dto?.Before });
                resLog = JsonSerializer.Serialize(new { updated });
                if (updated == 0) return NoContent();
                return Ok(new { updated });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }

        // ─────────────────────────── POST /archive-all ─────────────────────────
        [HttpPost("archive-all")]
        public async Task<IActionResult> ArchiveAll([FromBody] ArchiveAllDto dto)
        {
            var sw = Stopwatch.StartNew();
            var epId = await LoggingHelper.LogEndpointCallAsync(_db, "ALERTS_ARCHIVE_ALL", HttpContext.Request.Path);
            var reqLog = JsonSerializer.Serialize(dto);
            var resLog = "";
            var status = 200;
            string? error = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                var sql = new StringBuilder(@"
UPDATE dbo.USER_ALERTS
SET ARCHIVED_AT = SYSUTCDATETIME()
WHERE USER_ID = @UserId
  AND ARCHIVED_AT IS NULL");

                if (dto?.OnlyRead == true)
                    sql.Append(" AND IS_READ = 1");

                if (dto?.Before is DateTime cutoff)
                    sql.Append(" AND CREATED_AT <= @Cutoff");

                var updated = await _db.ExecuteAsync(sql.ToString(), new { UserId = userId, Cutoff = dto?.Before });
                resLog = JsonSerializer.Serialize(new { updated });
                if (updated == 0) return NoContent();
                return Ok(new { updated });
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
                await LoggingHelper.LogRequestResponseAsync(_db, epId, reqLog, resLog, status, error, (int)sw.ElapsedMilliseconds);
            }
        }
    }
}
