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
        public string TicketNumber { get; set; }
        public DateTime IssueTime { get; set; }
    }

    public struct FareInfo
    {
        public string FromStation { get; set; }
        public string ToStation { get; set; }
        public int FromZone { get; set; }
        public int ToZone { get; set; }
        public int FareCents { get; set; }
        public string FromStationName { get; set; }
        public string ToStationName { get; set; }
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

        [NonAction]
        private TicketData IssueTicketInternal(int valueCents, string issuingStation, byte ticketType)
        {
            using var connection = new SqlConnection(_connectionString);
            connection.Open();

            using var transaction = connection.BeginTransaction();

            // 1. Generate ticket number
            long ticketNumber = GenerateTicketNumberOnDB(connection, transaction);

            // 2. Get cryptographic keys
            var (signingKey, xorKey) = FrtTicket.GetCurrentKeys(connection, transaction);

            // 3. Encode ticket
            string ticketString = FrtTicket.EncodeTicket(
                ticketNumber: ticketNumber,
                valueCents: valueCents,
                issuingStation: issuingStation,
                issueDateTime: DateTime.UtcNow,
                ticketType: ticketType,
                signingKey: signingKey,
                xorObfuscatorKey: xorKey);

            // 4. Store in database
            SaveTicket(connection, transaction,
                ticketNumber: ticketNumber,
                valueCents: valueCents,
                issuingStation: issuingStation,
                ticketType: ticketType,
                ticketString: ticketString);

            transaction.Commit();

            return new TicketData
            {
                TicketString = ticketString,
                TicketNumber = ticketNumber.ToString(),
                IssueTime = DateTime.UtcNow
            };
        }

        [HttpGet("currentdatetime")]
        public IActionResult GetCurrentDateTime()
        {
            return Ok(DateTime.Now);
        }

        // Get fare between two stations
        [HttpGet("fare")]
        public IActionResult GetFare([FromQuery] FareRequest request)
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

                // Get station information and zones
                using var cmd = new SqlCommand(@"
                    SELECT 
                        fs.StationCode as FromCode,
                        fs.EnglishStationName as FromName,
                        fs.ZoneID as FromZone,
                        ts.StationCode as ToCode,
                        ts.EnglishStationName as ToName,
                        ts.ZoneID as ToZone
                    FROM Stations fs
                    CROSS JOIN Stations ts
                    WHERE fs.StationCode = @fromStation 
                      AND ts.StationCode = @toStation
                      AND fs.IsActive = 1 
                      AND ts.IsActive = 1", connection);

                cmd.Parameters.AddWithValue("@fromStation", request.FromStation.ToUpper());
                cmd.Parameters.AddWithValue("@toStation", request.ToStation.ToUpper());

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return NotFound("One or both station codes not found or inactive");
                }

                var fromZone = reader.GetInt32("FromZone");
                var toZone = reader.GetInt32("ToZone");
                var fromName = reader.GetString("FromName");
                var toName = reader.GetString("ToName");

                reader.Close();

                // Get fare from FareRules table
                using var fareCmd = new SqlCommand(@"
                    SELECT FareCents 
                    FROM FareRules 
                    WHERE FromZone = @fromZone AND ToZone = @toZone", connection);

                fareCmd.Parameters.AddWithValue("@fromZone", fromZone);
                fareCmd.Parameters.AddWithValue("@toZone", toZone);

                var fareResult = fareCmd.ExecuteScalar();
                if (fareResult == null)
                {
                    return NotFound($"No fare rule found for zone {fromZone} to zone {toZone}");
                }

                var fareCents = Convert.ToInt32(fareResult);

                var fareInfo = new FareInfo
                {
                    FromStation = request.FromStation.ToUpper(),
                    ToStation = request.ToStation.ToUpper(),
                    FromZone = fromZone,
                    ToZone = toZone,
                    FareCents = fareCents,
                    FromStationName = fromName,
                    ToStationName = toName
                };

                return Ok(fareInfo);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Fare lookup failed: {ex.Message}");
            }
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
                var ticketData = IssueTicketInternal(
                    request.ValueCents,
                    request.IssuingStation!,
                    (byte)request.TicketType);

                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ticket issuance failed: {ex.Message}");
            }
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

        [HttpGet("issuedebugticket")]
        public IActionResult IssueDebugTicket()
        {
            if (!_debugMode)
            {
                return StatusCode(403, "Debug mode is not enabled");
            }

            try
            {
                var ticketData = IssueTicketInternal(
                    300,    // Fixed debug value
                    "JLL",  // 俊霖路 station code
                    255);   // Debug ticket type

                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Debug ticket issuance failed: {ex.Message}");
            }
        }
    }

    public class FareRequest
    {
        [Required(ErrorMessage = "From station is required")]
        [StringLength(3, MinimumLength = 3, ErrorMessage = "From station code must be 3 characters")]
        [RegularExpression(@"^[A-Za-z]+$", ErrorMessage = "From station code must be letters only")]
        public required string FromStation { get; set; }

        [Required(ErrorMessage = "To station is required")]
        [StringLength(3, MinimumLength = 3, ErrorMessage = "To station code must be 3 characters")]
        [RegularExpression(@"^[A-Za-z]+$", ErrorMessage = "To station code must be letters only")]
        public required string ToStation { get; set; }
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