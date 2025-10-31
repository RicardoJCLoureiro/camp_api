namespace SPARC_API.DTOs
{
    /// <summary>
    /// Final reset step payload:
    /// - Token identifies the reset request record.
    /// - NewPassword is the new hashed password.
    /// - Code is the MFA one-time passcode for confirmation.
    /// </summary>
    public class ResetPasswordDto
    {
        public string Token { get; set; } = null!;
        public string NewPassword { get; set; } = null!;
        public string Code { get; set; } = null!;
    }
}
