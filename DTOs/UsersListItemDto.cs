// DTOs/UsersListItemDto.cs
namespace SPARC_API.DTOs
{
    public class UsersListItemDto
    {
        public int UserId { get; init; }
        public string Name { get; init; } = "";
        public string Surname { get; init; } = "";
        public string Email { get; init; } = "";
        public string? LanguagePreference { get; init; }
        public string? ProfilePictureUrl { get; init; }
        public bool IsActive { get; init; }
        public bool IsMfaEnabled { get; init; }

        // Details (all optional)
        public DateTime? BirthDate { get; init; }
        public string? Gender { get; init; }
        public string? IdentityNumber { get; init; }
        public string? BloodType { get; init; }
        public string? AddressLine1 { get; init; }
        public string? AddressLine2 { get; init; }
        public string? City { get; init; }
        public string? StateProvince { get; init; }
        public string? PostalCode { get; init; }
        public string? Country { get; init; }
        public string? PhoneNumber { get; init; }
        public string? EmergencyContactName { get; init; }
        public string? EmergencyContactPhone { get; init; }
        public string? EmergencyContactRelationship { get; init; }
        public string? Allergies { get; init; }
        public string? MedicalConditions { get; init; }

        // Audit
        public string CreatedBy { get; init; } = "";
        public DateTime CreatedAt { get; init; }
        public string? UpdatedBy { get; init; }
        public DateTime? UpdatedAt { get; init; }
    }
}
