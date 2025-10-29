// Models/SmtpSettings.cs
namespace SPARC_API.Models
{
    public class SmtpSettings
    {
        public string Host { get; set; } = "";
        public int Port { get; set; }              // "587" will bind fine to int
        public string User { get; set; } = "";
        public string Password { get; set; } = ""; // <-- renamed from Pass
        public bool EnableSsl { get; set; } = true;
        public string From { get; set; } = "";
    }
}