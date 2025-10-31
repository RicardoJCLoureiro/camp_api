namespace SPARC_API.DTOs
{
    /// <summary>
    /// Bulk archive command.
    /// - Before: optional cutoff date (<=).
    /// - OnlyRead: if true, archive only those that are read.
    /// </summary>
    public record ArchiveAllDto
    {
        public DateTime? Before { get; init; }
        public bool OnlyRead { get; init; } = false;
    }
}
