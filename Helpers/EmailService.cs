using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using System.Text;
using System.Net;
using SPARC_API.Helpers;

namespace SPARC_API.Models
{
    public class EmailService
    {
        private readonly IConfiguration _configuration;
        private readonly EmailTemplateService _templateService;

        // DI: pulls SMTP settings from IConfiguration and resolves the template engine.
        public EmailService(IConfiguration configuration, EmailTemplateService templateService)
        {
            _configuration = configuration;
            _templateService = templateService;
        }

        // Sends a password-reset email using the localized template.
        // Inputs:
        //   toEmail   → recipient address
        //   language  → "en", "pt", "es", "fr", "zh" (fallback to "en")
        //   fullName  → used for personalization tokens inside the template
        //   resetLink → front-end link for resetting the password
        // Reads:
        //   Smtp:Host, Smtp:Port, Smtp:User, Smtp:Password, Smtp:EnableSsl, Smtp:From
        public async Task SendResetPasswordEmailAsync(string toEmail, string language, string fullName, string resetLink)
        {
            // 1) Get subject/body from the template service (HTML preferred; TXT fallback).
            var (subject, body) = await _templateService.GetResetPasswordTemplateAsync(language, fullName, resetLink);

            // 2) Configure SmtpClient from appsettings (credentials over STARTTLS by default).
            //    NOTE: SmtpClient implements IDisposable; consider disposing (see suggestions).
            var smtpClient = new SmtpClient(_configuration["Smtp:Host"])
            {
                Port = int.Parse(_configuration["Smtp:Port"]),
                Credentials = new NetworkCredential(_configuration["Smtp:User"], _configuration["Smtp:Password"]),
                EnableSsl = bool.Parse(_configuration["Smtp:EnableSsl"])
            };

            // 3) Compose the message. UTF-8 to avoid garbled accents in subject/body.
            var mailMessage = new MailMessage
            {
                From = new MailAddress(_configuration["Smtp:From"]),
                Subject = subject,
                Body = body,
                IsBodyHtml = true,          // HTML templates may be used
                SubjectEncoding = Encoding.UTF8,
                BodyEncoding = Encoding.UTF8
            };
            mailMessage.To.Add(toEmail);

            // 4) Fire-and-forget send (async). Exceptions propagate to caller.
            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}
