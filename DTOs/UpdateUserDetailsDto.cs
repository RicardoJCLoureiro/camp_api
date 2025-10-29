// DTOs/UpdateUserDetailsDto.cs
using System;

namespace SPARC_API.DTOs
{
    // All fields optional — we will only update those provided (partial update)
    public class UpdateUserDetailsDto
    {
        // USERS table (safe profile fields)
        public string? Name { get; set; }
        public string? Surname { get; set; }
        public string? LanguagePreference { get; set; }
        public string? ProfilePictureUrl { get; set; }

        // USER_DETAILS table
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
    }
}
