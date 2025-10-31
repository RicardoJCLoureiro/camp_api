using System;
using System.Data;
using System.Threading.Tasks;
using Dapper;

namespace SPARC_API.Helpers
{
    public static class LoggingHelper
    {
        /// <summary>
        /// Inserts a row into LOG_ENDPOINT_CALLS and returns its ID.
        /// Expected schema:
        ///   LOG_ENDPOINT_CALLS(
        ///     ID INT IDENTITY PK,
        ///     NAME NVARCHAR(...),
        ///     PATH NVARCHAR(...),
        ///     CREATED_AT DATETIME DEFAULT GETDATE()
        ///   )
        /// Typical use:
        ///   - Call at controller entry to capture an endpoint invocation.
        /// </summary>
        public static async Task<int> LogEndpointCallAsync(
            IDbConnection conn,
            string name,
            string path)
        {
            var sql = @"
INSERT INTO LOG_ENDPOINT_CALLS (NAME, PATH)
VALUES (@Name, @Path);
SELECT CAST(SCOPE_IDENTITY() AS INT);";

            // Returns the generated ID for correlation in subsequent logs.
            return await conn.ExecuteScalarAsync<int>(sql, new { Name = name, Path = path });
        }

        /// <summary>
        /// Inserts a request/response log row and (optionally) an error row.
        /// LOG_REQUESTS_RESPONSES schema (expected):
        ///   ID INT IDENTITY PK,
        ///   ENDPOINT_ID INT FK -> LOG_ENDPOINT_CALLS.ID,
        ///   REQUEST_BODY NVARCHAR(MAX),
        ///   RESPONSE_BODY NVARCHAR(MAX),
        ///   STATUS INT,                 -- HTTP status code
        ///   TIMESTAMP DEFAULT GETDATE(),
        ///   RESPONSE_TIME INT NULL      -- ms (optional)
        ///
        /// ERROR_LOG schema (expected):
        ///   ID INT IDENTITY PK,
        ///   LOG_ENDPOINT_ID INT,        -- ties back to endpoint call
        ///   REFERENCE_ID NVARCHAR(...) NULL, -- external correlation id (optional)
        ///   ERROR_MESSAGE NVARCHAR(...),
        ///   ERROR_DETAILS NVARCHAR(MAX),
        ///   OCCURRED_AT DEFAULT GETDATE(),
        ///   DATA_PAYLOAD NVARCHAR(MAX)  -- request data for forensics
        ///
        /// Behavior:
        ///   - Always inserts into LOG_REQUESTS_RESPONSES.
        ///   - If errorDetails present → also inserts into ERROR_LOG.
        /// Returns:
        ///   - The LOG_REQUESTS_RESPONSES.ID created.
        /// </summary>
        public static async Task<int> LogRequestResponseAsync(
            IDbConnection conn,
            int endpointId,
            string? requestBody,
            string? responseBody,
            int status,
            string? errorDetails,
            int? responseTime = null)
        {
            // 1) Insert request/response row
            var insertReqResSql = @"
INSERT INTO LOG_REQUESTS_RESPONSES
    (ENDPOINT_ID, REQUEST_BODY, RESPONSE_BODY, STATUS, RESPONSE_TIME)
VALUES
    (@EndpointId, @RequestBody, @ResponseBody, @Status, @ResponseTime);
SELECT CAST(SCOPE_IDENTITY() AS INT);";

            int reqResId = await conn.ExecuteScalarAsync<int>(
                insertReqResSql,
                new
                {
                    EndpointId = endpointId,
                    RequestBody = requestBody ?? string.Empty,
                    ResponseBody = responseBody ?? string.Empty,
                    Status = status,
                    ResponseTime = responseTime
                }
            );

            // 2) If error present, insert an ERROR_LOG row referencing the same endpointId.
            if (!string.IsNullOrWhiteSpace(errorDetails))
            {
                // Derive a short message (first non-empty line) from the details.
                string errorMessage = errorDetails.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0];

                var insertErrorSql = @"
INSERT INTO ERROR_LOG
    (LOG_ENDPOINT_ID, REFERENCE_ID, ERROR_MESSAGE, ERROR_DETAILS, DATA_PAYLOAD)
VALUES
    (@LogEndpointId, @ReferenceId, @ErrorMessage, @ErrorDetails, @DataPayload);";

                await conn.ExecuteAsync(
                    insertErrorSql,
                    new
                    {
                        LogEndpointId = endpointId,      // note: not reqResId; ties to endpoint call
                        ReferenceId = (string?)null,     // optional correlation id placeholder
                        ErrorMessage = errorMessage,
                        ErrorDetails = errorDetails,
                        DataPayload = requestBody ?? string.Empty
                    }
                );
            }

            return reqResId;
        }

        /// <summary>
        /// Updates an existing request/response row after the response is known.
        /// Primary key: LOG_REQUESTS_RESPONSES.ID (ensure the table uses 'ID' as PK).
        /// Typical usage:
        ///   - Log early with a placeholder, then update with final response/time.
        /// </summary>
        public static async Task UpdateLogRequestResponseAsync(
            IDbConnection conn,
            int logId,
            string? responseBody,
            int status,
            int? responseTime = null)
        {
            var sql = @"
UPDATE LOG_REQUESTS_RESPONSES
   SET RESPONSE_BODY = @ResponseBody,
       STATUS        = @Status,
       RESPONSE_TIME = @ResponseTime
 WHERE ID = @LogId;";

            await conn.ExecuteAsync(
                sql,
                new
                {
                    LogId = logId,
                    ResponseBody = responseBody ?? string.Empty,
                    Status = status,
                    ResponseTime = responseTime
                }
            );
        }

        /// <summary>
        /// Direct error logger for non-request contexts.
        /// Returns the ERROR_LOG.ID generated.
        /// Useful for background jobs, agents, or failures before a response exists.
        /// </summary>
        public static async Task<int> LogErrorAsync(
            IDbConnection conn,
            int endpointId,
            string errorMessage,
            string errorDetails,
            string? referenceId = null,
            string? dataPayload = null)
        {
            var sql = @"
INSERT INTO ERROR_LOG
    (LOG_ENDPOINT_ID, REFERENCE_ID, ERROR_MESSAGE, ERROR_DETAILS, DATA_PAYLOAD)
VALUES
    (@EndpointId, @ReferenceId, @ErrorMessage, @ErrorDetails, @DataPayload);
SELECT CAST(SCOPE_IDENTITY() AS INT);";

            return await conn.ExecuteScalarAsync<int>(
                sql,
                new
                {
                    EndpointId = endpointId,
                    ReferenceId = referenceId,
                    ErrorMessage = errorMessage,
                    ErrorDetails = errorDetails,
                    DataPayload = dataPayload ?? string.Empty
                }
            );
        }
    }
}
