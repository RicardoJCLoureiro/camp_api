// DTOs/AlertsDtos.cs
using System;
using System.Collections.Generic;

namespace SPARC_API.DTOs
{
    public sealed class AlertListItemDto
    {
        public long Id { get; set; }
        public string Title { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public string Severity { get; set; } = "info"; // maps ALERT_SEVERITY.CODE
        public bool Read { get; set; }
        public string? Source { get; set; }
        public string? SourceRef { get; set; }
    }

    public sealed class AlertsSummaryDto
    {
        public int UnreadCount { get; set; }
        public IEnumerable<AlertListItemDto> Items { get; set; } = Array.Empty<AlertListItemDto>();
    }

    public sealed class AlertsListRequestDto
    {
        // Optional; if null, defaults to current user. Only "super" (userId==1) can query others.
        public int? UserId { get; set; }

        // "active" (default) = not archived and not expired; "archived" = archived; "all"
        public string Status { get; set; } = "active";

        // Optional severity filter: "info" | "warning" | "critical"
        public string? Severity { get; set; }

        // Simple search over title/body
        public string? Search { get; set; }

        // Pagination
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 20;
    }

    public sealed class AlertsMarkRequestDto
    {
        // Which alerts to affect
        public long[] Ids { get; set; } = Array.Empty<long>();
    }
}
