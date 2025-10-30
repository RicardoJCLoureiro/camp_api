using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SPARC_API.Helpers;
using System.Data;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace SPARC_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class AlertsController : ControllerBase
    {
        private readonly IDbConnection _db;

        public AlertsController(IDbConnection db)
        {
            _db = db;
        }

        // ───────────────────────────────── DTOs ─────────────────────────────────
        public class AlertListItemDto
        {
            public int Id { get; set; }
            public string Title { get; set; } = "";
            public string Body { get; set; } = "";
            public string CreatedAt { get; set; } = "";    // ISO 8601 UTC
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

        public class CreateAlertDto
        {
            public string Title { get; set; } = "";
            public string Body { get; set; } = "";
            public string Severity { get; set; } = "info";
        }

        // ─────────────────────────────── helpers ────────────────────────────────
        private bool TryGetUserId(out int userId)
        {
            var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            return int.TryParse(sub, out userId);
        }

        private static AlertListItemDto MapRow(dynamic r) => new AlertListItemDto
        {
            Id = (int)r.Id,
            Title = (string)r.Title,
            Body = (string)(r.Body ?? ""),
            CreatedAt = ((DateTime)r.CreatedAtUtc).ToUniversalTime().ToString("o"),
            Severity = string.IsNullOrEmpty((string?)r.SeverityCode) ? "info" : ((string)r.SeverityCode),
            IsRead = (bool)r.IsRead
        };

        // ───────────────────────────── summary (bell) ───────────────────────────
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
WHERE USER_ID = @UserId AND READ_AT IS NULL AND ARCHIVED_AT IS NULL 
  AND (EXPIRES_AT IS NULL OR EXPIRES_AT > SYSUTCDATETIME());

SELECT TOP (@Take)
       ua.ALERT_ID    AS Id,
       ua.TITLE       AS Title,
       ua.BODY        AS Body,
       ua.CREATED_AT  AS CreatedAtUtc,
       CASE WHEN ua.READ_AT IS NULL THEN CAST(0 AS bit) ELSE CAST(1 AS bit) END AS IsRead,
       s.CODE         AS SeverityCode
FROM dbo.USER_ALERTS ua
LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE ua.USER_ID = @UserId
  AND ua.ARCHIVED_AT IS NULL
  AND (ua.EXPIRES_AT IS NULL OR ua.EXPIRES_AT > SYSUTCDATETIME())
ORDER BY ua.CREATED_AT DESC;";

                using var multi = await _db.QueryMultipleAsync(sql, new { UserId = userId, Take = take });
                int unreadCount = await multi.ReadFirstAsync<int>();
                var rows = (await multi.ReadAsync()).ToList();
                var items = rows.Select(MapRow).ToList();

                var payload = new AlertsSummaryDto { UnreadCount = unreadCount, Items = items };
                resLog = JsonSerializer.Serialize(new { unreadCount = payload.UnreadCount, items = items.Count });
                return Ok(payload);
            }
            catch (Exception ex)
            {
                statusCode = 500; errorInfo = ex.ToString();
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

                var sbWhere = new System.Text.StringBuilder("ua.USER_ID = @UserId AND ua.ARCHIVED_AT IS NULL AND (ua.EXPIRES_AT IS NULL OR ua.EXPIRES_AT > SYSUTCDATETIME())");
                if (onlyUnread) sbWhere.Append(" AND ua.READ_AT IS NULL");
                if (!string.IsNullOrWhiteSpace(severity)) sbWhere.Append(" AND s.CODE = @Severity");

                string sql = $@"
SELECT COUNT(1)
FROM dbo.USER_ALERTS ua
LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
WHERE {sbWhere};

WITH Paged AS (
  SELECT
    ua.ALERT_ID    AS Id,
    ua.TITLE       AS Title,
    ua.BODY        AS Body,
    ua.CREATED_AT  AS CreatedAtUtc,
    CASE WHEN ua.READ_AT IS NULL THEN CAST(0 AS bit) ELSE CAST(1 AS bit) END AS IsRead,
    s.CODE         AS SeverityCode,
    ROW_NUMBER() OVER (ORDER BY ua.CREATED_AT DESC) AS rn
  FROM dbo.USER_ALERTS ua
  LEFT JOIN dbo.ALERT_SEVERITY s ON s.SEVERITY_ID = ua.SEVERITY_ID
  WHERE {sbWhere}
)
SELECT Id, Title, Body, CreatedAtUtc, IsRead, SeverityCode
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
                var items = rows.Select(MapRow).ToList();

                var payload = new AlertsPageDto { Items = items, Page = p, PageSize = ps, TotalCount = total };
                resLog = JsonSerializer.Serialize(new { total = payload.TotalCount, count = items.Count });
                return Ok(payload);
            }
            catch (Exception ex)
            {
                statusCode = 500; errorInfo = ex.ToString();
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

        // ────────────────────────────── mark all read ───────────────────────────
        [HttpPost("mark-all-read")]
        public async Task<IActionResult> MarkAllRead()
        {
            if (!TryGetUserId(out var userId))
                return Unauthorized(new { error = "Invalid token claims." });

            var sql = @"UPDATE dbo.USER_ALERTS SET READ_AT = SYSUTCDATETIME() WHERE USER_ID = @UserId AND READ_AT IS NULL;";
            int updated = await _db.ExecuteAsync(sql, new { UserId = userId });
            return Ok(new { updated });
        }

        // ───────────────────────────── archive all ──────────────────────────────
        [HttpPost("archive-all")]
        public async Task<IActionResult> ArchiveAll()
        {
            if (!TryGetUserId(out var userId))
                return Unauthorized(new { error = "Invalid token claims." });

            var sql = @"UPDATE dbo.USER_ALERTS SET ARCHIVED_AT = SYSUTCDATETIME() WHERE USER_ID = @UserId AND ARCHIVED_AT IS NULL;";
            int updated = await _db.ExecuteAsync(sql, new { UserId = userId });
            return Ok(new { updated });
        }

        // ────────────────────────── demo create ─────────────────────
        [HttpPost("demo-create")]
        public async Task<IActionResult> CreateDemo([FromBody] CreateAlertDto dto)
        {
            if (!TryGetUserId(out var userId))
                return Unauthorized(new { error = "Invalid token claims." });

            var sql = @"
DECLARE @SeverityId INT = (SELECT TOP 1 SEVERITY_ID FROM ALERT_SEVERITY WHERE CODE = @Code);
IF @SeverityId IS NULL SET @SeverityId = (SELECT TOP 1 SEVERITY_ID FROM ALERT_SEVERITY WHERE CODE = 'info');

INSERT INTO dbo.USER_ALERTS (USER_ID, SEVERITY_ID, TITLE, BODY, SOURCE, SOURCE_REF, CREATED_AT)
VALUES (@UserId, @SeverityId, @Title, @Body, 'demo', NULL, SYSUTCDATETIME());

SELECT TOP 1
    ALERT_ID AS Id,
    TITLE AS Title,
    BODY AS Body,
    CREATED_AT AS CreatedAtUtc,
    CAST(0 AS bit) AS IsRead,
    (SELECT CODE FROM ALERT_SEVERITY WHERE SEVERITY_ID = @SeverityId) AS SeverityCode
FROM dbo.USER_ALERTS
WHERE USER_ID = @UserId
ORDER BY ALERT_ID DESC;";

            var row = await _db.QueryFirstAsync(sql, new { UserId = userId, Title = dto.Title, Body = dto.Body, Code = dto.Severity });
            var item = MapRow(row);
            return Ok(item);
        }
    }
}
