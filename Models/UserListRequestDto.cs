namespace SPARC_API.Models
{
    // Request payload for paged user listing.
    // Controllers/UsersController.List expects this shape.
    public class UserListRequestDto
    {
        /// <summary>
        /// The tenant / top-entity for which to list users.
        /// </summary>
        public int TopEntityId { get; set; }

        /// <summary>
        /// 1-based page index.
        /// </summary>
        public int Page { get; set; } = 1;

        /// <summary>
        /// Number of items per page.
        /// </summary>
        public int PageSize { get; set; } = 20;
    }
}
