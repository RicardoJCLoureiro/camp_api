namespace SPARC_API.DTOs
{
    /// <summary>
    /// Flattened view model combining USERS + USER_DETAILS + audit fields.
    /// Returned by GET /api/users/me/details.
    /// </summary>
    public class UserDetailsDto
    {
        // Identity and profile
        public int UserId { get; set; }
        public string Name { get; set; } = "";
        public string Surname { get; set; } = "";
        public string Email { get; set; } = "";
        public string? LanguagePreference { get; set; }
        public string? ProfilePictureUrl { get; set; }

        // Status flags
        public bool IsActive { get; set; }
        public bool IsMfaEnabled { get; set; }

        // Personal info
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

        // Emergency + medical
        public string? EmergencyContactName { get; set; }
        public string? EmergencyContactPhone { get; set; }
        public string? EmergencyContactRelationship { get; set; }
        public string? Allergies { get; set; }
        public string? MedicalConditions { get; set; }

        // Audit metadata
        public string? CreatedBy { get; set; }
        public DateTime? CreatedAt { get; set; }
        public string? UpdatedBy { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }
}
