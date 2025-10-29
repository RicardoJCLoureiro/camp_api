// DTOs/ChangePasswordDto.cs
namespace SPARC_API.DTOs
{
    // Passwords arrive already hashed (client-side SHA-256), per your current flow
    public class ChangePasswordDto
    {
        public string CurrentPasswordHash { get; set; } = "";
        public string NewPasswordHash { get; set; } = "";
    }
}
