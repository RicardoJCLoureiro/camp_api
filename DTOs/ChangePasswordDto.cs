namespace SPARC_API.DTOs
{
    /// <summary>
    /// Change-my-password request payload.
    /// Passwords arrive pre-hashed by the client (e.g., SHA-256).
    /// </summary>
    public class ChangePasswordDto
    {
        public string CurrentPasswordHash { get; set; } = "";
        public string NewPasswordHash { get; set; } = "";
    }
}
