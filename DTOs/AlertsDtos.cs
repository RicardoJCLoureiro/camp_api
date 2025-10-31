using System;
using System.Collections.Generic;

namespace SPARC_API.DTOs
{
    /// <summary>
    /// Lightweight alert item for list/summary displays (e.g., bell dropdown).
    /// </summary>
    public class AlertListItemDto
    {
        public long Id { get; set; }

        // Main text
        public string Title { get; set; } = default!;
        public string? Body { get; set; }                 // preview in list/summary

        // Timestamps
        public DateTime CreatedAt { get; set; }
        public DateTime? ReadAt { get; set; }
        public DateTime? ArchivedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }

        // Read state
        public bool Read { get; set; }

        // Severity
        public int SeverityId { get; set; }
        public string Severity { get; set; } = default!;  // code
        public string SeverityName { get; set; } = default!;
        public int SeverityRank { get; set; }
        public string? ColorHex { get; set; }

        // Source
        public string? Source { get; set; }
        public string? SourceRef { get; set; }
    }

    /// <summary>
    /// Summary payload: unread count + a small batch of latest alerts.
    /// </summary>
    public sealed class AlertsSummaryDto
    {
        public int UnreadCount { get; set; }
        public IEnumerable<AlertListItemDto> Items { get; set; } = Array.Empty<AlertListItemDto>();
    }

    /// <summary>
    /// Query parameters for GET /api/alerts (paged list).
    /// </summary>
    public sealed class AlertsListRequestDto
    {
        /// <summary>
        /// Target user (optional). If null, defaults to current user.
        /// Only “super” (userId == 1) may query others.
        /// </summary>
        public int? UserId { get; set; }

        /// <summary>
        /// "active" (default) = not archived & not expired; "archived"; "all"
        /// </summary>
        public string Status { get; set; } = "active";

        /// <summary>
        /// Optional severity filter: "info" | "warning" | "critical"
        /// </summary>
        public string? Severity { get; set; }

        /// <summary>
        /// Simple LIKE search over title/body.
        /// </summary>
        public string? Search { get; set; }

        /// <summary>Filter only unread items.</summary>
        public bool? OnlyUnread { get; set; }

        /// <summary>Filter only read items.</summary>
        public bool? OnlyRead { get; set; }

        // Pagination controls (1-based page)
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 20;
    }

    /// <summary>
    /// IDs to mark read/unread or archive/unarchive.
    /// </summary>
    public sealed class AlertsMarkRequestDto
    {
        public long[] Ids { get; set; } = Array.Empty<long>();
    }
}
