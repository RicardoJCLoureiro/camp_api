namespace SPARC_API.DTOs
{
    public class MfaSetupResponseDto
    {
        public string QrCodeImage { get; set; } = null!;  // data:image/png;base64,...
        public string ManualEntryKey { get; set; } = null!; // Base32 secret
    }
}