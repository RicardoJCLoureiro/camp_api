// Controllers/AlertsController.cs
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using SPARC_API.Helpers;

namespace SPARC_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class AlertsController : ControllerBase
    {
        private readonly IDbConnection _db;
        public AlertsController(IDbConnection db) => _db = db;

        // ───────────────────────────────── DTOs ─────────────────────────────────
        public class AlertListItemDto
        {
            public int Id { get; set; }
            public string Title { get; set; } = "";
            public string CreatedAt { get; set; } = "";    // ISO 8601 (UTC) for FE
            public string Severity { get; set; } = "info"; // 'info' | 'warning' | 'critical'
            public bool IsRead { get; set; }
        }

        public class AlertsSummaryDto
        {
            public int UnreadCount { get; set; }
            public IEnumerable<AlertListItemDto> Items { get; set; } = Enumerable.Empty<AlertListItemDto>();
        }

        public class AlertsPageDto
        {
            public IEnumerable<AlertListItemDto> Items { get; set; } = Enumerable.Empty<AlertListItemDto>();
            public int Page { get; set; }
            public int PageSize { get; set; }
            public int TotalCount { get; set; }
        }

        public class MarkReadDto
        {
            public int[] Ids { get; set; } = Array.Empty<int>();
        }

        // ─────────────────────────────── helpers ────────────────────────────────
        private bool TryGetUserId(out int userId)
        {
            var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            return int.TryParse(sub, out userId);
        }

        private static AlertListItemDto MapRowToItem(dynamic r) => new AlertListItemDto
        {
            Id = (int)r.Id,
            Title = (string)r.Title,
            CreatedAt = ((DateTime)r.CreatedAtUtc).ToUniversalTime().ToString("o"),
            Severity = string.IsNullOrEmpty((string?)r.SeverityCode) ? "info" : ((string)r.SeverityCode),
            IsRead = (bool)r.IsRead
        };

        // ───────────────────────────── summary (bell) ───────────────────────────
        /// <summary>
        /// GET /api/alerts/summary?max=6
        /// Returns unread count and last N alerts for the authenticated user.
        /// </summary>
        [HttpGet("summary")]
        public async Task<IActionResult> GetSummary([FromQuery] int? max = null)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, "AlertsController.GetSummary", HttpContext.Request.Path + Request.QueryString);
            string reqLog = JsonSerializer.Serialize(new { max });
            string resLog = "";
            int statusCode = 200;
            string? errorInfo = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                int take = Math.Clamp(max ?? 6, 1, 50);

                var sql = @"
SELECT COUNT(1) AS UnreadCount
FROM dbo.USER_ALERTS
WHERE USER_ID = @UserId AND READ_AT IS NULL;

SELECT TOP (@Take)
       ua.ALERT_ID    AS Id,
       ua.TITLE       AS Title,
       ua.CREATED_AT  AS CreatedAtUtc,
       CASE WHEN ua.READ_AT IS NULL THEN CAST(0 AS bit) ELSE CAST(1 AS bit) END AS IsRead,
       s.CODE         AS SeverityCode
FROM dbo.USER_ALERTS ua
LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE ua.USER_ID = @UserId
ORDER BY ua.CREATED_AT DESC;";

                using var multi = await _db.QueryMultipleAsync(sql, new { UserId = userId, Take = take });

                int unreadCount = await multi.ReadFirstAsync<int>();
                var rows = (await multi.ReadAsync()).ToList();

                var items = rows.Select(MapRowToItem).ToList();

                var payload = new AlertsSummaryDto
                {
                    UnreadCount = unreadCount,
                    Items = items
                };

                resLog = JsonSerializer.Serialize(new { unreadCount = payload.UnreadCount, items = items.Count });
                return Ok(payload);
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

        // ─────────────────────────────── paged list ─────────────────────────────
        /// <summary>
        /// GET /api/alerts?page=1&pageSize=20&onlyUnread=false&severity=warning
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> List(
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20,
            [FromQuery] bool onlyUnread = false,
            [FromQuery] string? severity = null)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, "AlertsController.List", HttpContext.Request.Path + Request.QueryString);
            string reqLog = JsonSerializer.Serialize(new { page, pageSize, onlyUnread, severity });
            string resLog = "";
            int statusCode = 200;
            string? errorInfo = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                int p = Math.Max(page, 1);
                int ps = Math.Clamp(pageSize, 1, 100);
                int offset = (p - 1) * ps;

                // build filters
                var sbWhere = new System.Text.StringBuilder("ua.USER_ID = @UserId");
                if (onlyUnread) sbWhere.Append(" AND ua.READ_AT IS NULL");
                if (!string.IsNullOrWhiteSpace(severity))
                    sbWhere.Append(" AND s.CODE = @Severity");

                string sql = $@"
SELECT COUNT(1)
FROM dbo.USER_ALERTS ua
LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE {sbWhere};

WITH Paged AS (
  SELECT
    ua.ALERT_ID    AS Id,
    ua.TITLE       AS Title,
    ua.CREATED_AT  AS CreatedAtUtc,
    CASE WHEN ua.READ_AT IS NULL THEN CAST(0 AS bit) ELSE CAST(1 AS bit) END AS IsRead,
    s.CODE         AS SeverityCode,
    ROW_NUMBER() OVER (ORDER BY ua.CREATED_AT DESC) AS rn
  FROM dbo.USER_ALERTS ua
  LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
  WHERE {sbWhere}
)
SELECT Id, Title, CreatedAtUtc, IsRead, SeverityCode
FROM Paged
WHERE rn BETWEEN @Offset + 1 AND @Offset + @PageSize
ORDER BY rn;";

                using var multi = await _db.QueryMultipleAsync(sql, new
                {
                    UserId = userId,
                    Severity = severity,
                    Offset = offset,
                    PageSize = ps
                });

                int total = await multi.ReadFirstAsync<int>();
                var rows = (await multi.ReadAsync()).ToList();
                var items = rows.Select(MapRowToItem).ToList();

                var payload = new AlertsPageDto
                {
                    Items = items,
                    Page = p,
                    PageSize = ps,
                    TotalCount = total
                };

                resLog = JsonSerializer.Serialize(new { total = payload.TotalCount, count = items.Count });
                return Ok(payload);
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

        // ────────────────────────────── mark as read ────────────────────────────
        /// <summary>
        /// POST /api/alerts/mark-read
        /// { "ids": [1,2,3] }
        /// Marks alerts as read for the authenticated user.
        /// </summary>
        [HttpPost("mark-read")]
        public async Task<IActionResult> MarkRead([FromBody] MarkReadDto dto)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, "AlertsController.MarkRead", HttpContext.Request.Path);
            string reqLog = JsonSerializer.Serialize(new { ids = dto?.Ids?.Length ?? 0 });
            string resLog = "";
            int statusCode = 200;
            string? errorInfo = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                if (dto?.Ids == null || dto.Ids.Length == 0)
                    return BadRequest(new { error = "noIds" });

                // Update only rows owned by this user
                var sql = @"
UPDATE dbo.USER_ALERTS
   SET READ_AT = SYSUTCDATETIME()
 WHERE USER_ID = @UserId
   AND ALERT_ID IN @Ids
   AND READ_AT IS NULL;";

                int updated = await _db.ExecuteAsync(sql, new { UserId = userId, Ids = dto.Ids });

                resLog = JsonSerializer.Serialize(new { updated });
                return Ok(new { updated });
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

        // Controllers/AlertsController.cs  (append inside class)
        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetById([FromRoute] int id)
        {
            var sw = Stopwatch.StartNew();
            int endpointLogId = await LoggingHelper.LogEndpointCallAsync(
                _db, "AlertsController.GetById", HttpContext.Request.Path + Request.QueryString);
            string reqLog = JsonSerializer.Serialize(new { id });
            string resLog = "";
            int statusCode = 200;
            string? errorInfo = null;

            try
            {
                if (!TryGetUserId(out var userId))
                    return Unauthorized(new { error = "Invalid token claims." });

                // NOTE: If you don't have CONTENT/MESSAGE in USER_ALERTS, coalesce to NULL safely.
                var sql = @"
SELECT 
    ua.ALERT_ID         AS Id,
    ua.TITLE            AS Title,
    ua.CREATED_AT       AS CreatedAtUtc,
    CASE WHEN ua.READ_AT IS NULL THEN CAST(0 AS bit) ELSE CAST(1 AS bit) END AS IsRead,
    s.CODE              AS SeverityCode,
    CAST(NULL AS nvarchar(max)) AS Content   -- replace with ua.CONTENT (or ua.MESSAGE) if you have it
FROM dbo.USER_ALERTS ua
LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE ua.USER_ID = @UserId AND ua.ALERT_ID = @Id;";

                var row = await _db.QueryFirstOrDefaultAsync(sql, new { UserId = userId, Id = id });
                if (row == null)
                {
                    statusCode = 404;
                    resLog = JsonSerializer.Serialize(new { error = "notFound" });
                    return NotFound(new { error = "notFound" });
                }

                var dto = new
                {
                    id = (int)row.Id,
                    title = (string)row.Title,
                    createdAt = ((DateTime)row.CreatedAtUtc).ToUniversalTime().ToString("o"),
                    severity = string.IsNullOrEmpty((string?)row.SeverityCode) ? "info" : ((string)row.SeverityCode),
                    isRead = (bool)row.IsRead,
                    content = (string?)row.Content // may be null if you haven't added a content column
                };

                resLog = JsonSerializer.Serialize(new { ok = true, hasContent = dto.content != null });
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

    }
}
