using Microsoft.AspNetCore.Mvc;
using System;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.ComponentModel.DataAnnotations;

namespace FrtAfcBackend.Controllers
{
    public struct TicketData
    {
        public string TicketString { get; set; }
        public DateTime IssueTime { get; set; }
    }

    [ApiController]
    [Route("api/v1/[controller]")]
    public class AfcController : ControllerBase
    {
        // Set this to false in production to disable debug ticket issuance and other stuff!!!!!
        private readonly bool _debugMode = true;

        private readonly string? _connectionString = Environment.GetEnvironmentVariable("SQLSERVER_CONNECTION_STRING");
        private const string TimeZoneId = "China Standard Time"; // Change to your metro's timezone

        // Wrapper to call the SP on the SQL Server to generate a ticket number
        [NonAction]
        public long GenerateTicketNumberOnDB(SqlConnection conn, SqlTransaction? transaction = null)
        {
            using var cmd = new SqlCommand("sp_GenerateTicketNumber", conn)
            {
                CommandType = CommandType.StoredProcedure,
                Transaction = transaction
            };

            var outputParam = new SqlParameter("@TicketNumber", SqlDbType.BigInt)
            {
                Direction = ParameterDirection.Output
            };
            cmd.Parameters.Add(outputParam);

            cmd.ExecuteNonQuery();

            long ticketNumber = (long)outputParam.Value;

            if (ticketNumber <= 0)
                throw new InvalidOperationException("Database generated invalid ticket number");

            return ticketNumber;
        }

        [HttpGet("currentdatetime")]
        public IActionResult GetCurrentDateTime()
        {
            return Ok(DateTime.Now);
        }

        // Ticket issuance function
        [HttpPost("issueticket")]
        public IActionResult IssueTicket([FromBody] TicketRequest request)
        {
            // Automatic model validation
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                try
                {
                    // 1. Generate ticket number
                    long ticketNumber = GenerateTicketNumberOnDB(connection, transaction);

                    // 2. Get cryptographic keys
                    var (signingKey, xorKey) = GetCurrentKeys(connection, transaction);

                    // 3. Encode ticket
                    string ticketString = FrtTicket.EncodeTicket(
                        ticketNumber: ticketNumber,
                        valueCents: request.ValueCents,
                        issuingStation: request.IssuingStation!,
                        issueDateTime: DateTime.UtcNow,
                        ticketType: (byte)request.TicketType,
                        signingKey: signingKey,
                        xorObfuscatorKey: xorKey);

                    // 4. Store in database
                    SaveTicket(connection, transaction,
                        ticketNumber: ticketNumber,
                        valueCents: request.ValueCents,
                        issuingStation: request.IssuingStation!,
                        ticketType: (byte)request.TicketType,
                        ticketString: ticketString);

                    transaction.Commit();

                    return Ok(new TicketData
                    {
                        TicketString = ticketString,
                        IssueTime = DateTime.UtcNow
                    });
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    return StatusCode(500, $"Ticket issuance failed: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Database error: {ex.Message}");
            }
        }

        private (ECDsa signingKey, byte[] xorKey) GetCurrentKeys(SqlConnection conn, SqlTransaction tx)
        {
            // First try to get existing valid keys
            var (signingKey, xorKey) = TryGetValidKeys(conn, tx);
            if (signingKey != null && xorKey != null)
            {
                return (signingKey, xorKey);
            }

            // Generate new keys if none exist or they're expired
            return GenerateNewKeys(conn, tx);
        }

        private (ECDsa? signingKey, byte[]? xorKey) TryGetValidKeys(SqlConnection conn, SqlTransaction tx)
        {
            using var cmd = new SqlCommand(
                @"SELECT TOP 1 sk.PrivateKey, ok.KeyBytes 
                FROM SigningKeys sk
                JOIN ObfuscatingKeys ok ON sk.KeyVersion = ok.KeyVersion
                WHERE sk.ExpiryDateTime > GETUTCDATE()
                ORDER BY sk.KeyVersion DESC",
                conn, tx);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
            {
                return (null, null);
            }

            var privateKey = reader.GetString(0);
            var xorKey = (byte[])reader.GetValue(1);

            var signingKey = ECDsa.Create();
            signingKey.ImportFromPem(privateKey);

            return (signingKey, xorKey);
        }

        private (ECDsa signingKey, byte[] xorKey) GenerateNewKeys(SqlConnection conn, SqlTransaction tx)
        {
            // Calculate expiry time (next 3 AM local time)
            var localTimeZone = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneId);
            var nowLocal = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, localTimeZone);
            var expiryLocal = nowLocal.Hour < 3
                ? new DateTime(nowLocal.Year, nowLocal.Month, nowLocal.Day, 3, 0, 0)
                : new DateTime(nowLocal.Year, nowLocal.Month, nowLocal.Day, 3, 0, 0).AddDays(1);
            var expiryUtc = TimeZoneInfo.ConvertTimeToUtc(expiryLocal, localTimeZone);

            // Generate new ECDSA key pair
            using var newSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKey = newSigningKey.ExportECPrivateKeyPem();
            var publicKey = newSigningKey.ExportSubjectPublicKeyInfoPem();

            // Generate new XOR key
            var newXorKey = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(newXorKey);

            // Get next key version
            var keyVersion = GetNextKeyVersion(conn, tx);

            // Store both keys
            using (var cmd = new SqlCommand(
                "INSERT INTO SigningKeys (PrivateKey, PublicKey, StartDateTime, ExpiryDateTime, KeyVersion) " +
                "VALUES (@privateKey, @publicKey, @start, @expiry, @version)",
                conn, tx))
            {
                cmd.Parameters.AddWithValue("@privateKey", privateKey);
                cmd.Parameters.AddWithValue("@publicKey", publicKey);
                cmd.Parameters.AddWithValue("@start", DateTime.UtcNow);
                cmd.Parameters.AddWithValue("@expiry", expiryUtc);
                cmd.Parameters.AddWithValue("@version", keyVersion);
                cmd.ExecuteNonQuery();
            }

            using (var cmd = new SqlCommand(
                "INSERT INTO ObfuscatingKeys (KeyBytes, StartDateTime, ExpiryDateTime, KeyVersion) " +
                "VALUES (@keyBytes, @start, @expiry, @version)",
                conn, tx))
            {
                cmd.Parameters.AddWithValue("@keyBytes", newXorKey);
                cmd.Parameters.AddWithValue("@start", DateTime.UtcNow);
                cmd.Parameters.AddWithValue("@expiry", expiryUtc);
                cmd.Parameters.AddWithValue("@version", keyVersion);
                cmd.ExecuteNonQuery();
            }

            // Return the new keys
            var returnKey = ECDsa.Create();
            returnKey.ImportFromPem(privateKey);

            return (returnKey, newXorKey);
        }

        private int GetNextKeyVersion(SqlConnection conn, SqlTransaction tx)
        {
            using var cmd = new SqlCommand(
                "SELECT ISNULL(MAX(KeyVersion), 0) + 1 FROM SigningKeys",
                conn, tx);
            return Convert.ToInt32(cmd.ExecuteScalar());
        }

        private void SaveTicket(
            SqlConnection conn,
            SqlTransaction tx,
            long ticketNumber,
            int valueCents,
            string issuingStation,
            byte ticketType,
            string ticketString)
        {
            using var cmd = new SqlCommand(
                @"INSERT INTO Tickets (
                    TicketNumber,
                    ValueCents,
                    IssuingStation,
                    IssueDateTime,
                    TicketType,
                    TicketState,
                    IsInvoiced
                ) VALUES (
                    @num, @value, @station, 
                    GETUTCDATE(), @type, 
                    1, 0)", // State 1 = Paid, not used
                conn, tx);

            cmd.Parameters.AddWithValue("@num", ticketNumber);
            cmd.Parameters.AddWithValue("@value", valueCents);
            cmd.Parameters.AddWithValue("@station", issuingStation);
            cmd.Parameters.AddWithValue("@type", ticketType);

            cmd.ExecuteNonQuery();
        }

        [HttpGet("IssueDebugTicket")]
        public IActionResult IssueDebugTicket()
        {
            if (!_debugMode)
            {
                return StatusCode(403, "Debug mode is not enabled");
            }

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                try
                {
                    // 1. Generate ticket number
                    long ticketNumber = GenerateTicketNumberOnDB(connection, transaction);

                    // 2. Get cryptographic keys
                    var (signingKey, xorKey) = GetCurrentKeys(connection, transaction);

                    // 3. Encode debug ticket
                    string ticketString = FrtTicket.EncodeTicket(
                        ticketNumber: ticketNumber,
                        valueCents: 300, // Fixed debug value
                        issuingStation: "JLL", // 俊霖路 station code
                        issueDateTime: DateTime.UtcNow,
                        ticketType: 255, // Debug ticket type
                        signingKey: signingKey,
                        xorObfuscatorKey: xorKey);

                    // 4. Store in database
                    SaveTicket(connection, transaction,
                        ticketNumber: ticketNumber,
                        valueCents: 300,
                        issuingStation: "JLL",
                        ticketType: 255, // Debug type
                        ticketString: ticketString);

                    transaction.Commit();

                    return Ok(new TicketData
                    {
                        TicketString = ticketString,
                        IssueTime = DateTime.UtcNow
                    });
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    return StatusCode(500, $"Debug ticket issuance failed: {ex.ToString()}");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Database error: {ex.Message}");
            }
        }
    }

    public class TicketRequest
    {
        [Required(ErrorMessage = "Issuing station is required")]
        [StringLength(3, MinimumLength = 3, ErrorMessage = "Station code must be 3 characters")]
        [RegularExpression(@"^[A-Z]+$", ErrorMessage = "Station code must be uppercase letters")]
        public required string IssuingStation { get; set; }

        [Required(ErrorMessage = "Ticket value is required")]
        [Range(1, 100000, ErrorMessage = "Value must be between 1 and 100000 cents")]
        public required int ValueCents { get; set; }

        [Required(ErrorMessage = "Ticket type is required")]
        [Range(0, 255, ErrorMessage = "Ticket type must be between 0 and 255")]
        public required int TicketType { get; set; }
    }

}