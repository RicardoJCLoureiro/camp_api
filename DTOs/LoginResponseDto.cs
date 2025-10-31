using System;

namespace SPARC_API.DTOs
{
    /// <summary>
    /// Response after successful login/refresh.
    /// Note: JWT is set in an HttpOnly cookie; Token property can be kept
    /// for backward compatibility if the frontend still reads it.
    /// </summary>
    public class LoginResponseDto
    {
        public string? Token { get; set; }  // cookie-first flow; optional
        public DateTime Expires { get; set; }

        // Unified user context: id, email, display name, avatar, roles, etc.
        public UserSession User { get; set; } = default!;
    }
}
