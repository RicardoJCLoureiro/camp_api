namespace SPARC_API.DTOs
{
    /// <summary>
    /// Bulk mark-all-read request.
    /// If <see cref="Before"/> is provided, only alerts created on or before that date are affected.
    /// </summary>
    public record ReadAllDto
    {
        public DateTime? Before { get; init; }
    }
}
