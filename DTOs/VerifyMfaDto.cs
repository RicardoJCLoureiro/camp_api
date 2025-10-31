namespace SPARC_API.DTOs
{
    /// <summary>
    /// Payload for verifying MFA code after setup.
    /// </summary>
    public class VerifyMfaDto
    {
        public string Code { get; set; } = null!;
    }
}
