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
        public EmailService(IConfiguration configuration, EmailTemplateService templateService)
        {
            _configuration = configuration;
            _templateService = templateService;
        }

        // Helpers/EmailService.cs
        public async Task SendResetPasswordEmailAsync(string toEmail, string language, string fullName, string resetLink)
        {
            var (subject, body) = await _templateService.GetResetPasswordTemplateAsync(language, fullName, resetLink);

            var smtpClient = new SmtpClient(_configuration["Smtp:Host"])
            {
                Port = int.Parse(_configuration["Smtp:Port"]),
                Credentials = new NetworkCredential(_configuration["Smtp:User"], _configuration["Smtp:Password"]),
                EnableSsl = bool.Parse(_configuration["Smtp:EnableSsl"])
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(_configuration["Smtp:From"]),
                Subject = subject,
                Body = body,
                IsBodyHtml = true,          // ← render HTML
                SubjectEncoding = Encoding.UTF8,
                BodyEncoding = Encoding.UTF8
            };
            mailMessage.To.Add(toEmail);

            await smtpClient.SendMailAsync(mailMessage);
        }
    }
}