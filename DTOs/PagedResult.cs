namespace SPARC_API.DTOs
{
    public class PagedResult<T>
    {
        public IEnumerable<T> Items { get; set; } = Enumerable.Empty<T>();
        public int TotalCount { get; set; }
        public int Page { get; set; }
        public int PageSize { get; set; }
        public int PageCount => (int)Math.Ceiling(TotalCount / (double)PageSize);
    }
}
