namespace SPARC_API.DTOs
{
    public class ResetPasswordDto
    {
        public string Token { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
        public string Code { get; set; } = null!;
    }
}
