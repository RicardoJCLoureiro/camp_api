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
        /// Matches: LOG_ENDPOINT_CALLS(ID, NAME, PATH, CREATED_AT default GETDATE()).
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

            return await conn.ExecuteScalarAsync<int>(sql, new { Name = name, Path = path });
        }

        /// <summary>
        /// Inserts into LOG_REQUESTS_RESPONSES. If errorDetails is not null/empty,
        /// also inserts a row into ERROR_LOG using the same endpointId and the request payload.
        ///
        /// LOG_REQUESTS_RESPONSES columns:
        ///   ID (IDENTITY), ENDPOINT_ID, REQUEST_BODY, RESPONSE_BODY, STATUS, TIMESTAMP default, RESPONSE_TIME
        ///
        /// ERROR_LOG columns:
        ///   ID, LOG_ENDPOINT_ID, REFERENCE_ID (nullable), ERROR_MESSAGE, ERROR_DETAILS, OCCURRED_AT default, DATA_PAYLOAD
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
            // 1) Insert request/response log
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

            // 2) If there was an error, also log to ERROR_LOG
            if (!string.IsNullOrWhiteSpace(errorDetails))
            {
                // Derive a short message from the first line of the details
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
                        LogEndpointId = endpointId,
                        ReferenceId = (string?)null, // you can set a correlation id or ticket id later
                        ErrorMessage = errorMessage,
                        ErrorDetails = errorDetails,
                        DataPayload = requestBody ?? string.Empty
                    }
                );
            }

            return reqResId;
        }

        /// <summary>
        /// Updates an existing LOG_REQUESTS_RESPONSES row.
        /// NOTE: your table PK is ID (not DETAIL_ID).
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
        /// Optional direct error logger if you ever want to log errors outside
        /// the request/response flow.
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