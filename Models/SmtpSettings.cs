// Models/SmtpSettings.cs
namespace SPARC_API.Models
{
    // Strongly-typed binding for "Smtp" section in appsettings.
    // Consumed by EmailService to send transactional emails (reset, etc.).
    public class SmtpSettings
    {
        // SMTP hostname (e.g., smtp.example.com)
        public string Host { get; set; } = "";

        // Port typically 587 for STARTTLS.
        public int Port { get; set; }              // "587" will bind fine to int

        // Auth username (mailbox or SMTP user).
        public string User { get; set; } = "";

        // Auth password (override via secrets/env in non-dev).
        public string Password { get; set; } = ""; // <-- renamed from Pass

        // STARTTLS toggle; true for port 587.
        public bool EnableSsl { get; set; } = true;

        // Default From: address for outbound emails.
        public string From { get; set; } = "";
    }
}
