// DTOs/AlertDto.cs
namespace SPARC_API.DTOs
{
    public class AlertDto
    {
        public int AlertId { get; set; }
        public string SeverityCode { get; set; } = default!;
        public string SeverityName { get; set; } = default!;
        public int SeverityRank { get; set; }
        public string? ColorHex { get; set; }
        public string Title { get; set; } = default!;
        public string? Body { get; set; }
        public string? Source { get; set; }
        public string? SourceRef { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ReadAt { get; set; }
        public DateTime? ArchivedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool IsRead { get; set; }
    }
}
