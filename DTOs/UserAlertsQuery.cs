// DTOs/UserAlertsQuery.cs
namespace SPARC_API.DTOs
{
    public record UserAlertsQuery
    {
        public int Page { get; init; } = 1;
        public int PageSize { get; init; } = 20;
        public bool OnlyUnread { get; init; } = false;
        public bool IncludeArchived { get; init; } = false;
        public string? Severity { get; init; } // "info" | "warning" | "critical"
        public string? Source { get; init; }
        public DateTime? Since { get; init; }
    }
}
