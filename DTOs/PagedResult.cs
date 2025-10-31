namespace SPARC_API.DTOs
{
    /// <summary>
    /// Generic paging envelope: use for lists to standardize pagination UI.
    /// </summary>
    public class PagedResult<T>
    {
        public IEnumerable<T> Items { get; set; } = Enumerable.Empty<T>();
        public int TotalCount { get; set; }
        public int Page { get; set; }           // 1-based
        public int PageSize { get; set; }
        public int PageCount => (int)Math.Ceiling(TotalCount / (double)PageSize);
    }
}
