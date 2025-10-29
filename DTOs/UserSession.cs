// DTOs/UserSession.cs
namespace SPARC_API.DTOs
{
    public class UserSession
    {
        public int UserId { get; init; }
        public string Email { get; init; } = "";
        public string Name { get; init; } = "";
        public string? ProfilePictureUrl { get; init; }
        public IEnumerable<string> Roles { get; init; } = Array.Empty<string>();
    }
}