namespace SPARC_API.Models
{
    // Strongly-typed binding for "Jwt" section in appsettings.
    // Used in Program.cs to configure token validation & minting.
    public class JwtSettings
    {
        // Symmetric signing key (HS256). In Dev/Prod, override via user-secrets / env.
        public string Key { get; set; } = null!;

        // Token issuer (should match validation parameters).
        public string Issuer { get; set; } = null!;

        // Intended audience for the token (frontend/app identifier).
        public string Audience { get; set; } = null!;

        // Access token lifetime (minutes).
        public int ExpireMinutes { get; set; }
    }
}
