// DTOs/LoginResponseDto.cs
using System;

namespace SPARC_API.DTOs
{
    public class LoginResponseDto
    {
        // We no longer return the raw JWT (it's set in an HttpOnly cookie).
        // Keep this property only if your frontend still reads it.
        // Otherwise, you can safely delete it.
        public string? Token { get; set; }

        public DateTime Expires { get; set; }

        // Unified user payload (id, email, name, profile picture, roles)
        public UserSession User { get; set; } = default!;
    }
}