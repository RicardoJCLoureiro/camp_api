using System;

namespace SPARC_API.Models
{
    public class UserWithDetailsDto
    {
        public int UserId { get; set; }
        public string Name { get; set; } = "";
        public string Surname { get; set; } = "";
        public string Email { get; set; } = "";
        public string? LanguagePreference { get; set; }
        public string? ProfilePictureUrl { get; set; }
        public string IsActive { get; set; } = "";
        public string IsMfaEnabled { get; set; } = "";
        public DateTime? BirthDate { get; set; }
        public string? Gender { get; set; }
        public string? IdentityNumber { get; set; }
        public string? BloodType { get; set; }
        public string? AddressLine1 { get; set; }
        public string? AddressLine2 { get; set; }
        public string? City { get; set; }
        public string? StateProvince { get; set; }
        public string? PostalCode { get; set; }
        public string? Country { get; set; }
        public string? PhoneNumber { get; set; }
        public string? EmergencyContactName { get; set; }
        public string? EmergencyContactPhone { get; set; }
        public string? EmergencyContactRelationship { get; set; }
        public string? Allergies { get; set; }
        public string? MedicalConditions { get; set; }
        public int TopEntityId { get; set; }
        public string TopEntityName { get; set; } = "";
        public string CreatedBy { get; set; } = "";
        public DateTime CreatedAt { get; set; }
        public string? UpdatedBy { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
