namespace SPARC_API.DTOs
{
    public class LoginWithMfaDto
    {
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string Code { get; set; } = null!;
    }
}