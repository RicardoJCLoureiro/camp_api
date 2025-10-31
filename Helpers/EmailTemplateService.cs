// Helpers/EmailTemplateService.cs
using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SPARC_API.Helpers
{
    public class EmailTemplateService
    {
        // Base folder: <bin>/EmailTemplates (copied on publish).
        // Consider ContentRootPath for dev friendliness (see suggestions).
        private readonly string _templateBasePath;

        private readonly ILogger<EmailTemplateService> _logger;

        // IConfiguration currently unused (ok), ILogger used for diagnostics.
        public EmailTemplateService(IConfiguration configuration, ILogger<EmailTemplateService> logger)
        {
            _templateBasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "EmailTemplates");
            _logger = logger;
        }

        // Returns (Subject, Body) for reset password emails.
        // Prefers HTML: "reset_password_<lang>.html" with <title> as subject.
        // Falls back to TXT: "reset_password_<lang>.txt" where first "Subject:" line becomes the subject.
        // Tokens replaced: {FullName}, {ResetLink}
        public async Task<(string Subject, string Body)> GetResetPasswordTemplateAsync(string language, string fullName, string resetLink)
        {
            _logger.LogInformation("Loading reset‐password template for language: {Lang}", language);

            // Normalize and map language codes.
            // Unknown codes fall back to English.
            string langCode = language.ToLower() switch
            {
                "pt" => "pt",
                "es" => "es",
                "fr" => "fr",
                "en" => "en",
                "zh" => "zh",
                _ => "en"
            };

            // 1) Try HTML template first.
            string htmlPath = Path.Combine(_templateBasePath, $"reset_password_{langCode}.html");
            if (!File.Exists(htmlPath))
            {
                _logger.LogWarning("HTML template not found ({Path}), falling back to TXT", htmlPath);
                htmlPath = null;
            }

            // 2) Precompute TXT path (used when HTML is missing).
            string textPath = Path.Combine(_templateBasePath, $"reset_password_{langCode}.txt");
            if (htmlPath == null && !File.Exists(textPath))
            {
                // Final fallback to English TXT if neither exists for the requested lang.
                _logger.LogWarning("TXT template not found ({Path}), falling back to English TXT", textPath);
                langCode = "en";
                textPath = Path.Combine(_templateBasePath, $"reset_password_en.txt");
            }

            // 3) If we have HTML, read it and extract the <title> for subject.
            if (htmlPath != null)
            {
                _logger.LogInformation("Using HTML template: {Path}", htmlPath);
                var html = await File.ReadAllTextAsync(htmlPath);

                // Token replacement (simple string.Replace).
                html = html.Replace("{FullName}", fullName)
                           .Replace("{ResetLink}", resetLink);

                // Use the <title> tag as subject if present; else generic default.
                var m = Regex.Match(html, @"<title>\s*(.+?)\s*</title>", RegexOptions.IgnoreCase);
                var subject = m.Success ? m.Groups[1].Value : "Password Reset Request";
                return (subject, html);
            }

            // 4) TXT fallback: first "Subject:" line wins; remainder is body.
            _logger.LogInformation("Using TXT template: {Path}", textPath);
            var txt = await File.ReadAllTextAsync(textPath);

            var lines = txt.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            string subjectLine = lines.FirstOrDefault(l => l.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase))
                                   ?? "Subject: Password Reset Request";

            var subjectTxt = subjectLine.Substring(subjectLine.IndexOf(':') + 1).Trim();

            // Body is everything after the "Subject:" line.
            var bodyTxt = string.Join(Environment.NewLine,
                lines.SkipWhile(l => !l.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase))
                     .Skip(1));

            // Token replacement for TXT.
            bodyTxt = bodyTxt.Replace("{FullName}", fullName)
                             .Replace("{ResetLink}", resetLink);

            return (subjectTxt, bodyTxt);
        }
    }
}
