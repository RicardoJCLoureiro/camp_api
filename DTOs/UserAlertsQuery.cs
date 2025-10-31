namespace SPARC_API.DTOs
{
    /// <summary>
    /// Query parameters for advanced user alert listing/filtering.
    /// Mirrors AlertsListRequestDto but for internal reuse.
    /// </summary>
    public record UserAlertsQuery
    {
        public int Page { get; init; } = 1;
        public int PageSize { get; init; } = 20;

        // Filter flags
        public bool OnlyUnread { get; init; } = false;
        public bool IncludeArchived { get; init; } = false;

        // Filtering metadata
        public string? Severity { get; init; } // "info" | "warning" | "critical"
        public string? Source { get; init; }

        // Optional date-based filter
        public DateTime? Since { get; init; }
    }
}
