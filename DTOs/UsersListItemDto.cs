namespace SPARC_API.DTOs
{
    /// <summary>
    /// Minimal projection used in paginated user lists.
    /// Returned by UsersController.List (admin view).
    /// </summary>
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

        // Optional detailed columns (from USER_DETAILS)
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

        // Emergency + medical info
        public string? EmergencyContactName { get; init; }
        public string? EmergencyContactPhone { get; init; }
        public string? EmergencyContactRelationship { get; init; }
        public string? Allergies { get; init; }
        public string? MedicalConditions { get; init; }

        // Audit info
        public string CreatedBy { get; init; } = "";
        public DateTime CreatedAt { get; init; }
        public string? UpdatedBy { get; init; }
        public DateTime? UpdatedAt { get; init; }
    }
}
