namespace SPARC_API.DTOs
{
    /// <summary>
    /// Triggers a reset link email in the specified language.
    /// </summary>
    public class ForgotPasswordDto
    {
        public string Email { get; set; } = null!;
        public string Language { get; set; } = null!;
    }
}
