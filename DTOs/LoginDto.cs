namespace SPARC_API.DTOs
{
    /// <summary>
    /// Standard login payload (email + hashed password).
    /// </summary>
    public class LoginDto
    {
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}
