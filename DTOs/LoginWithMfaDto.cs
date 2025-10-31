namespace SPARC_API.DTOs
{
    /// <summary>
    /// MFA login payload: email + hashed password + one-time code.
    /// </summary>
    public class LoginWithMfaDto
    {
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string Code { get; set; } = null!;
    }
}
