// DTOs/ArchiveAllDto.cs
namespace SPARC_API.DTOs
{
    public record ArchiveAllDto
    {
        public DateTime? Before { get; init; }
        public bool OnlyRead { get; init; } = false;
    }
}
