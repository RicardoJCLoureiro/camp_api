namespace SPARC_API.DTOs
{
    /// <summary>
    /// Lightweight session object returned after login/refresh.
    /// Represents current user context stored in JWT and used by frontend.
    /// </summary>
    public class UserSession
    {
        public int UserId { get; init; }
        public string Email { get; init; } = "";
        public string Name { get; init; } = "";
        public string? ProfilePictureUrl { get; init; }

        /// <summary>
        /// Set of role names (e.g., "Admin", "Manager").
        /// </summary>
        public IEnumerable<string> Roles { get; init; } = Array.Empty<string>();
    }
}
