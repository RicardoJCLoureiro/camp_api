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
        private readonly string _templateBasePath;
        private readonly ILogger<EmailTemplateService> _logger;

        public EmailTemplateService(IConfiguration configuration, ILogger<EmailTemplateService> logger)
        {
            _templateBasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "EmailTemplates");
            _logger = logger;
        }

        public async Task<(string Subject, string Body)> GetResetPasswordTemplateAsync(string language, string fullName, string resetLink)
        {
            _logger.LogInformation("Loading reset‐password template for language: {Lang}", language);

            // pick html first
            string langCode = language.ToLower() switch
            {
                "pt" => "pt",
                "es" => "es",
                "fr" => "fr",
                "en" => "en",
                "zh" => "zh",
                _ => "en"
            };

            string htmlPath = Path.Combine(_templateBasePath, $"reset_password_{langCode}.html");
            if (!File.Exists(htmlPath))
            {
                _logger.LogWarning("HTML template not found ({Path}), falling back to TXT", htmlPath);
                htmlPath = null;
            }

            string textPath = Path.Combine(_templateBasePath, $"reset_password_{langCode}.txt");
            if (htmlPath == null && !File.Exists(textPath))
            {
                _logger.LogWarning("TXT template not found ({Path}), falling back to English TXT", textPath);
                langCode = "en";
                textPath = Path.Combine(_templateBasePath, $"reset_password_en.txt");
            }

            // If we have an HTML template & it exists, load that:
            if (htmlPath != null)
            {
                _logger.LogInformation("Using HTML template: {Path}", htmlPath);
                var html = await File.ReadAllTextAsync(htmlPath);

                // perform replacements
                html = html.Replace("{FullName}", fullName)
                           .Replace("{ResetLink}", resetLink);

                // extract <title> as subject
                var m = Regex.Match(html, @"<title>\s*(.+?)\s*</title>", RegexOptions.IgnoreCase);
                var subject = m.Success ? m.Groups[1].Value : "Password Reset Request";
                return (subject, html);
            }

            // else load the TXT fallback
            _logger.LogInformation("Using TXT template: {Path}", textPath);
            var txt = await File.ReadAllTextAsync(textPath);
            var lines = txt.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            string subjectLine = lines.FirstOrDefault(l => l.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase))
                                   ?? "Subject: Password Reset Request";
            var subjectTxt = subjectLine.Substring(subjectLine.IndexOf(':') + 1).Trim();
            var bodyTxt = string.Join(Environment.NewLine,
                lines.SkipWhile(l => !l.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase))
                     .Skip(1));

            bodyTxt = bodyTxt.Replace("{FullName}", fullName)
                             .Replace("{ResetLink}", resetLink);

            return (subjectTxt, bodyTxt);
        }
    }
}
