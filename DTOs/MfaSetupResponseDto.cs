namespace SPARC_API.DTOs
{
    /// <summary>
    /// Response for MFA setup: inline QR image (data URL) + Base32 secret
    /// for manual entry in authenticator apps.
    /// </summary>
    public class MfaSetupResponseDto
    {
        public string QrCodeImage { get; set; } = null!;   // data:image/png;base64,...
        public string ManualEntryKey { get; set; } = null!; // Base32 secret
    }
}
