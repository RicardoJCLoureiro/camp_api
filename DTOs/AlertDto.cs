namespace SPARC_API.DTOs
{
    /// <summary>
    /// Full alert projection for a single item view.
    /// Includes severity metadata, status timestamps, and read flag.
    /// Used by AlertsController.GetById.
    /// </summary>
    public class AlertDto
    {
        public int AlertId { get; set; }

        // ALERT_SEVERITY fields
        public string SeverityCode { get; set; } = default!;
        public string SeverityName { get; set; } = default!;
        public int SeverityRank { get; set; }
        public string? ColorHex { get; set; }

        // Content
        public string Title { get; set; } = default!;
        public string? Body { get; set; }

        // Optional provenance fields
        public string? Source { get; set; }
        public string? SourceRef { get; set; }

        // Lifecycle
        public DateTime CreatedAt { get; set; }
        public DateTime? ReadAt { get; set; }
        public DateTime? ArchivedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }

        // Convenience flag derived from ReadAt
        public bool IsRead { get; set; }
    }
}
