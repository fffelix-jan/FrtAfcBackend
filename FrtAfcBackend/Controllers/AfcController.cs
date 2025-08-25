using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
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

    public struct StationInfo
    {
        public string StationCode { get; set; }
        public string EnglishName { get; set; }
        public string ChineseName { get; set; }
        public int ZoneId { get; set; }
        public bool IsActive { get; set; }
    }

    [ApiController]
    [Route("api/v1/[controller]")]
    public class AfcController : PermissionControllerBase
    {
        // Set this to false in production to disable debug ticket issuance and other stuff!!!!!
        private readonly bool _debugMode = false;

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
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        public IActionResult GetCurrentDateTime()
        {
            return Ok(new { 
                currentDateTime = DateTime.Now,
                serverTimeZone = TimeZoneId,
                username = GetUsername(),
                userId = GetUserId(),
                authenticated = true
            });
        }

        // Get station information by station code (REQUIRES ViewStations permission)
        [HttpGet("getstationname")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ViewStations)]
        public IActionResult GetStationName([FromQuery] StationRequest request)
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

                using var cmd = new SqlCommand(@"
                    SELECT 
                        StationCode,
                        EnglishStationName,
                        ChineseStationName,
                        ZoneID,
                        IsActive
                    FROM Stations 
                    WHERE StationCode = @stationCode", connection);

                cmd.Parameters.AddWithValue("@stationCode", request.StationCode.ToUpper());

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return NotFound($"Station with code '{request.StationCode.ToUpper()}' not found");
                }

                var stationInfo = new StationInfo
                {
                    StationCode = reader.GetString("StationCode"),
                    EnglishName = reader.GetString("EnglishStationName"),
                    ChineseName = reader.GetString("ChineseStationName"),
                    ZoneId = reader.GetInt32("ZoneID"),
                    IsActive = reader.GetBoolean("IsActive")
                };

                return Ok(stationInfo);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Station lookup failed: {ex.Message}");
            }
        }

        // Get fare between two stations (REQUIRES ViewFares permission)
        [HttpGet("fare")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ViewFares)]
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

                // Use the shared helper method
                var fareInfo = GetFareInfoInternal(connection, null, request.FromStation, request.ToStation);
                
                if (fareInfo == null)
                {
                    return NotFound("One or both station codes not found or inactive, or no fare rule exists");
                }

                return Ok(fareInfo.Value);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Fare lookup failed: {ex.Message}");
            }
        }

        // Issue full fare ticket (REQUIRES IssueFullFareTickets permission)
        [HttpPost("issueticket/full")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.IssueFullFareTickets)]
        public IActionResult IssueFullFareTicket([FromBody] TicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ticketData = IssueTicketInternal(request.ValueCents, request.IssuingStation!, 0); // Type 0 = Full Fare
                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Full fare ticket issuance failed: {ex.Message}");
            }
        }

        // Issue student ticket (REQUIRES IssueStudentTickets permission)
        [HttpPost("issueticket/student")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.IssueStudentTickets)]
        public IActionResult IssueStudentTicket([FromBody] TicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ticketData = IssueTicketInternal(request.ValueCents, request.IssuingStation!, 1); // Type 1 = Student
                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Student ticket issuance failed: {ex.Message}");
            }
        }

        // Issue senior ticket (REQUIRES IssueSeniorTickets permission)
        [HttpPost("issueticket/senior")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.IssueSeniorTickets)]
        public IActionResult IssueSeniorTicket([FromBody] TicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ticketData = IssueTicketInternal(request.ValueCents, request.IssuingStation!, 2); // Type 2 = Senior
                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Senior ticket issuance failed: {ex.Message}");
            }
        }

        // Issue free entry ticket (REQUIRES IssueFreeEntryTickets permission)
        [HttpPost("issueticket/free")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.IssueFreeEntryTickets)]
        public IActionResult IssueFreeEntryTicket([FromBody] TicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ticketData = IssueTicketInternal(0, request.IssuingStation!, 3); // Type 3 = Free Entry, Value = 0
                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Free entry ticket issuance failed: {ex.Message}");
            }
        }

        // Issue day pass ticket (REQUIRES IssueDayPassTickets permission)
        [HttpPost("issueticket/daypass")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.IssueDayPassTickets)]
        public IActionResult IssueDayPassTicket([FromBody] DayPassTicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                // Get current day pass price from database
                int dayPassPrice = GetDayPassPriceCents();

                var ticketData = IssueTicketInternal(dayPassPrice, request.IssuingStation!, 4);
                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Day pass ticket issuance failed: {ex.Message}");
            }
        }

        // Reissue damaged ticket (REQUIRES ReissueTickets permission)
        [HttpPost("reissueticket")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ReissueTickets)]
        public IActionResult ReissueTicket([FromBody] ReissueTicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                // 1. Validate the original ticket exists and get its details
                using var validateCmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, TicketType, TicketState, IsInvoiced
                    FROM Tickets 
                    WHERE TicketNumber = @originalTicketNumber", connection, transaction);

                validateCmd.Parameters.AddWithValue("@originalTicketNumber", request.OriginalTicketNumber);

                using var reader = validateCmd.ExecuteReader();
                if (!reader.Read())
                {
                    transaction.Rollback();
                    return NotFound($"Original ticket '{request.OriginalTicketNumber}' not found");
                }

                var originalTicketState = reader.GetByte("TicketState");
                var originalValueCents = reader.GetInt32("ValueCents");
                var originalIssuingStation = reader.GetString("IssuingStation");
                var originalTicketType = reader.GetByte("TicketType");
                var originalIsInvoiced = reader.GetBoolean("IsInvoiced");

                reader.Close();

                // 2. Check if ticket is in a valid state for reissue (allow paid or entered station)
                if (originalTicketState != 1 && originalTicketState != 2)
                {
                    transaction.Rollback();
                    return BadRequest($"Ticket '{request.OriginalTicketNumber}' cannot be reissued (current state: {originalTicketState}). Only tickets in 'Paid' (1) or 'Entered Station' (2) states can be reissued.");
                }

                // 3. Use provided values or fall back to original ticket values (preserve original ticket type)
                int newValueCents = request.ValueCents > 0 ? request.ValueCents : originalValueCents;
                string newIssuingStation = !string.IsNullOrEmpty(request.IssuingStation) ? request.IssuingStation : originalIssuingStation;
                byte newTicketType = originalTicketType; // Always use original ticket type

                // 4. Generate new ticket number
                long newTicketNumber = GenerateTicketNumberOnDB(connection, transaction);

                // 5. Get cryptographic keys
                var (signingKey, xorKey) = FrtTicket.GetCurrentKeys(connection, transaction);

                // 6. Encode new ticket
                string newTicketString = FrtTicket.EncodeTicket(
                    ticketNumber: newTicketNumber,
                    valueCents: newValueCents,
                    issuingStation: newIssuingStation,
                    issueDateTime: DateTime.UtcNow,
                    ticketType: newTicketType,
                    signingKey: signingKey,
                    xorObfuscatorKey: xorKey);

                // 7. Insert new ticket with same state, type, and invoice status as original
                SaveTicketWithStateAndInvoice(connection, transaction,
                    ticketNumber: newTicketNumber,
                    valueCents: newValueCents,
                    issuingStation: newIssuingStation,
                    ticketType: newTicketType,
                    ticketString: newTicketString,
                    ticketState: originalTicketState,
                    isInvoiced: originalIsInvoiced); // Preserve invoice status

                // 8. Invalidate original ticket (set state to 4 = Reissued/Invalid)
                using var invalidateCmd = new SqlCommand(@"
                    UPDATE Tickets 
                    SET TicketState = 4
                    WHERE TicketNumber = @originalTicketNumber", connection, transaction);

                invalidateCmd.Parameters.AddWithValue("@originalTicketNumber", request.OriginalTicketNumber);
                invalidateCmd.ExecuteNonQuery();

                transaction.Commit();

                var newTicketData = new TicketData
                {
                    TicketString = newTicketString,
                    TicketNumber = newTicketNumber.ToString(),
                    IssueTime = DateTime.UtcNow
                };

                return Ok(new
                {
                    originalTicket = request.OriginalTicketNumber,
                    originalTicketState = originalTicketState,
                    originalTicketType = originalTicketType,
                    originalIssuingStation = originalIssuingStation,
                    originalValueCents = originalValueCents, // Add this line
                    originalIsInvoiced = originalIsInvoiced,
                    replacementTicket = newTicketData,
                    replacementTicketState = originalTicketState,
                    replacementTicketType = originalTicketType,
                    replacementValueCents = newValueCents, // Add this line
                    replacementIsInvoiced = originalIsInvoiced,
                    message = $"Ticket successfully reissued (original state: {originalTicketState}, type: {originalTicketType}, invoice status: {originalIsInvoiced} preserved)",
                    reissuedBy = GetUsername(),
                    reissueTime = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ticket reissuance failed: {ex.Message}");
            }
        }

        // Helper method to save ticket with specific state and invoice status
        [NonAction]
        private void SaveTicketWithStateAndInvoice(
            SqlConnection conn,
            SqlTransaction tx,
            long ticketNumber,
            int valueCents,
            string issuingStation,
            byte ticketType,
            string ticketString,
            byte ticketState,
            bool isInvoiced)
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
                    GETUTCDATE(), @type, @state, @invoiced)",
                conn, tx);

            cmd.Parameters.AddWithValue("@num", ticketNumber);
            cmd.Parameters.AddWithValue("@value", valueCents);
            cmd.Parameters.AddWithValue("@station", issuingStation);
            cmd.Parameters.AddWithValue("@type", ticketType);
            cmd.Parameters.AddWithValue("@state", ticketState);
            cmd.Parameters.AddWithValue("@invoiced", isInvoiced);

            cmd.ExecuteNonQuery();
        }

        // Issue invoice for ticket (REQUIRES IssueInvoices permission)
        [HttpPost("issueinvoice")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.IssueInvoices)]
        public IActionResult IssueInvoice([FromBody] IssueInvoiceRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                string ticketNumber;

                // Check if input is a QR code (ticket string) or ticket number
                if (request.TicketInput.Length > 20) // QR codes are much longer than ticket numbers
                {
                    // Input is likely a QR code (ticket string), decode it
                    try
                    {
                        // Get cryptographic keys for decoding
                        var (signingKey, xorKey) = FrtTicket.TryGetValidKeys(connection, transaction);
                        if (signingKey == null || xorKey == null)
                        {
                            transaction.Rollback();
                            return StatusCode(500, "Unable to retrieve decoding keys from server");
                        }

                        // Try to decode the QR code
                        bool decoded = FrtTicket.TryDecodeTicket(
                            encodedTicket: request.TicketInput,
                            signingKey: signingKey,
                            xorObfuscatorKey: xorKey,
                            out long decodedTicketNumber,
                            out int decodedValueCents,
                            out string decodedIssuingStation,
                            out DateTime decodedIssueDateTime,
                            out byte decodedTicketType);

                        if (!decoded)
                        {
                            transaction.Rollback();
                            return BadRequest("Invalid QR code or unable to decode ticket");
                        }

                        ticketNumber = decodedTicketNumber.ToString();

                        // Dispose the keys properly
                        signingKey.Dispose();
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        return BadRequest($"QR code decoding failed: {ex.Message}");
                    }
                }
                else
                {
                    // Input is a ticket number
                    ticketNumber = request.TicketInput;
                }

                // Now proceed with the standard invoice logic using the ticket number
                using var ticketCmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, IssueDateTime, TicketType, TicketState, IsInvoiced
                    FROM Tickets 
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                ticketCmd.Parameters.AddWithValue("@ticketNumber", ticketNumber);

                using var reader = ticketCmd.ExecuteReader();
                if (!reader.Read())
                {
                    transaction.Rollback();
                    return NotFound($"Ticket '{ticketNumber}' not found");
                }

                var isInvoiced = reader.GetBoolean("IsInvoiced");
                var ticketType = reader.GetByte("TicketType");
                var ticketState = reader.GetByte("TicketState");
                var valueCents = reader.GetInt32("ValueCents");
                var issuingStation = reader.GetString("IssuingStation");
                var issueDateTime = reader.GetDateTime("IssueDateTime");

                reader.Close();

                // Check if already invoiced
                if (isInvoiced)
                {
                    transaction.Rollback();
                    return BadRequest($"Ticket '{ticketNumber}' has already been invoiced");
                }

                // Check if ticket can be invoiced (only tickets with value > 0)
                if (valueCents <= 0)
                {
                    transaction.Rollback();
                    return BadRequest($"Cannot issue invoice for free tickets (value: ¥{valueCents / 100.0:F2})");
                }

                // Update invoice status
                using var updateCmd = new SqlCommand(@"
                    UPDATE Tickets 
                    SET IsInvoiced = 1
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                updateCmd.Parameters.AddWithValue("@ticketNumber", ticketNumber);
                updateCmd.ExecuteNonQuery();

                transaction.Commit();

                return Ok(new
                {
                    ticketNumber = ticketNumber,
                    ticketType = ticketType,
                    ticketState = ticketState,
                    valueCents = valueCents,
                    valueYuan = valueCents / 100.0m,
                    issuingStation = issuingStation,
                    issueDateTime = issueDateTime,
                    invoicedBy = GetUsername(),
                    invoiceTime = DateTime.UtcNow,
                    inputMethod = request.TicketInput.Length > 20 ? "qr_code" : "ticket_number",
                    message = $"Invoice issued successfully for ticket {ticketNumber}"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Invoice issuance failed: {ex.Message}");
            }
        }

        // Refund ticket (REQUIRES RefundTickets permission)
        [HttpPost("refundticket")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.RefundTickets)]
        public IActionResult RefundTicket([FromBody] RefundTicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                string ticketNumber;

                // Check if input is a QR code (ticket string) or ticket number
                if (request.TicketInput.Length > 20) // QR codes are much longer than ticket numbers
                {
                    // Input is likely a QR code (ticket string), decode it
                    try
                    {
                        // Get cryptographic keys for decoding
                        var (signingKey, xorKey) = FrtTicket.TryGetValidKeys(connection, transaction);
                        if (signingKey == null || xorKey == null)
                        {
                            transaction.Rollback();
                            return StatusCode(500, "Unable to retrieve decoding keys from server");
                        }

                        // Try to decode the QR code
                        bool decoded = FrtTicket.TryDecodeTicket(
                            encodedTicket: request.TicketInput,
                            signingKey: signingKey,
                            xorObfuscatorKey: xorKey,
                            out long decodedTicketNumber,
                            out int decodedValueCents,
                            out string decodedIssuingStation,
                            out DateTime decodedIssueDateTime,
                            out byte decodedTicketType);

                        if (!decoded)
                        {
                            transaction.Rollback();
                            return BadRequest("Invalid QR code or unable to decode ticket");
                        }

                        ticketNumber = decodedTicketNumber.ToString();

                        // Dispose the keys properly
                        signingKey.Dispose();
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        return BadRequest($"QR code decoding failed: {ex.Message}");
                    }
                }
                else
                {
                    // Input is a ticket number
                    ticketNumber = request.TicketInput;
                }

                // Now proceed with the refund logic using the ticket number
                using var ticketCmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, IssueDateTime, TicketType, TicketState, IsInvoiced
                    FROM Tickets 
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                ticketCmd.Parameters.AddWithValue("@ticketNumber", ticketNumber);

                using var reader = ticketCmd.ExecuteReader();
                if (!reader.Read())
                {
                    transaction.Rollback();
                    return NotFound($"Ticket '{ticketNumber}' not found");
                }

                var isInvoiced = reader.GetBoolean("IsInvoiced");
                var ticketType = reader.GetByte("TicketType");
                var ticketState = reader.GetByte("TicketState");
                var valueCents = reader.GetInt32("ValueCents");
                var issuingStation = reader.GetString("IssuingStation");
                var issueDateTime = reader.GetDateTime("IssueDateTime");

                reader.Close();

                // Check if ticket can be refunded (only state 1 = Paid and not invoiced)
                if (ticketState != 1)
                {
                    transaction.Rollback();
                    return BadRequest($"Ticket '{ticketNumber}' cannot be refunded. Only tickets in 'Paid' state can be refunded (current state: {ticketState})");
                }

                if (isInvoiced)
                {
                    transaction.Rollback();
                    return BadRequest($"Ticket '{ticketNumber}' cannot be refunded because it has already been invoiced");
                }

                // Check if ticket has value to refund (free tickets cannot be refunded)
                if (valueCents <= 0)
                {
                    transaction.Rollback();
                    return BadRequest($"Cannot refund free tickets (value: ¥{valueCents / 100.0:F2})");
                }

                // Update ticket state to "Refunded" (5)
                using var updateCmd = new SqlCommand(@"
                    UPDATE Tickets 
                    SET TicketState = 5
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                updateCmd.Parameters.AddWithValue("@ticketNumber", ticketNumber);
                updateCmd.ExecuteNonQuery();

                transaction.Commit();

                return Ok(new
                {
                    ticketNumber = ticketNumber,
                    ticketType = ticketType,
                    originalTicketState = ticketState,
                    newTicketState = 5, // Refunded
                    valueCents = valueCents,
                    valueYuan = valueCents / 100.0m,
                    issuingStation = issuingStation,
                    issueDateTime = issueDateTime,
                    refundedBy = GetUsername(),
                    refundTime = DateTime.UtcNow,
                    inputMethod = request.TicketInput.Length > 20 ? "qr_code" : "ticket_number",
                    message = $"Ticket {ticketNumber} refunded successfully for ¥{valueCents / 100.0:F2}"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ticket refund failed: {ex.Message}");
            }
        }

        [HttpPost("getticketinfo")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ViewTickets)]
        public IActionResult GetTicketInfo([FromBody] GetTicketInfoRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (string.IsNullOrWhiteSpace(request.TicketInput))
                return BadRequest("Ticket input cannot be null or empty");

            string ticketNumber;
            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                // If the ticket input is long it is assumed to be a QR code.
                if (request.TicketInput.Trim().Length > 20)
                {
                    using var transaction = connection.BeginTransaction();
                    try
                    {
                        var (signingKey, xorKey) = FrtTicket.TryGetValidKeys(connection, transaction);
                        if (signingKey == null || xorKey == null)
                        {
                            transaction.Rollback();
                            return StatusCode(500, "Unable to retrieve decoding keys from server");
                        }

                        bool decoded = FrtTicket.TryDecodeTicket(
                            encodedTicket: request.TicketInput.Trim(),
                            signingKey: signingKey,
                            xorObfuscatorKey: xorKey,
                            out long decodedTicketNumber,
                            out int decodedValueCents,
                            out string decodedIssuingStation,
                            out DateTime decodedIssueDateTime,
                            out byte decodedTicketType);

                        if (!decoded)
                        {
                            transaction.Rollback();
                            return BadRequest("Invalid QR code or unable to decode ticket");
                        }
                        ticketNumber = decodedTicketNumber.ToString();
                        signingKey.Dispose();
                        transaction.Rollback(); // No database changes were made.
                    }
                    catch (Exception ex)
                    {
                        return BadRequest($"QR code decoding failed: {ex.Message}");
                    }
                }
                else
                {
                    // Validate ticket number format for manual input
                    if (!System.Text.RegularExpressions.Regex.IsMatch(request.TicketInput.Trim(), @"^\d+$"))
                    {
                        return BadRequest("Invalid ticket number format. Ticket number must contain only digits.");
                    }
                    ticketNumber = request.TicketInput.Trim();
                }

                using var cmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, IssueDateTime, TicketType, TicketState, IsInvoiced 
                    FROM Tickets 
                    WHERE TicketNumber = @ticketNumber", connection);
                cmd.Parameters.AddWithValue("@ticketNumber", ticketNumber);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                    return NotFound($"Ticket number '{ticketNumber}' not found in system");

                var valueCents = reader.GetInt32(reader.GetOrdinal("ValueCents"));
                var issueDateTimeUtc = reader.GetDateTime(reader.GetOrdinal("IssueDateTime"));

                // Convert UTC time to local time zone
                var timeZoneInfo = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneId);
                var issueDateTime = TimeZoneInfo.ConvertTimeFromUtc(issueDateTimeUtc, timeZoneInfo);

                var ticketInfo = new
                {
                    TicketNumber = reader.GetInt64(reader.GetOrdinal("TicketNumber")),
                    ValueCents = valueCents,
                    ValueYuan = valueCents / 100.0m, // Convert cents to yuan
                    IssuingStation = reader.GetString(reader.GetOrdinal("IssuingStation")),
                    IssueDateTime = issueDateTime, // Now in local time
                    TicketType = reader.GetByte(reader.GetOrdinal("TicketType")),
                    TicketState = reader.GetByte(reader.GetOrdinal("TicketState")),
                    IsInvoiced = reader.GetBoolean(reader.GetOrdinal("IsInvoiced")),
                    InputMethod = request.TicketInput.Length > 20 ? "qr_code" : "ticket_number"
                };

                return Ok(ticketInfo);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return StatusCode(500, $"Ticket lookup failed: {ex.Message}");
            }
        }

        // Validate ticket at entry faregate (REQUIRES ValidateTickets permission)
        [HttpPost("validateticketatentry")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ValidateTickets)]
        public IActionResult ValidateTicketAtEntry([FromBody] ValidateTicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // ValidatingStation is required for entry validation
            if (string.IsNullOrEmpty(request.ValidatingStation))
            {
                return BadRequest("Validating station is required for entry validation");
            }

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                // Get ticket information
                using var ticketCmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, IssueDateTime, TicketType, TicketState
                    FROM Tickets 
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                ticketCmd.Parameters.AddWithValue("@ticketNumber", request.TicketNumber);

                using var reader = ticketCmd.ExecuteReader();
                if (!reader.Read())
                {
                    transaction.Rollback();
                    return BadRequest("Ticket not found");
                }

                var ticketType = reader.GetByte("TicketType");
                var ticketState = reader.GetByte("TicketState");
                var issuingStation = reader.GetString("IssuingStation");
                var issueDateTime = reader.GetDateTime("IssueDateTime");
                var valueCents = reader.GetInt32("ValueCents");

                reader.Close();

                // Check ticket state
                if (ticketState != 1)
                {
                    transaction.Rollback();
                    return BadRequest("Ticket is not in valid state for entry");
                }

                // Handle different ticket types
                switch (ticketType)
                {
                    case 3: // Free Exit ticket
                        transaction.Rollback();
                        return BadRequest("Free exit tickets cannot be used for entry");

                    case 4: // Day Pass
                        // Check if ticket is for current day
                        var ticketDate = issueDateTime.Date;
                        var currentDate = DateTime.Now.Date;
                        
                        if (ticketDate != currentDate)
                        {
                            transaction.Rollback();
                            return BadRequest("Day pass is not valid for today");
                        }
                        break;

                    default: // Regular tickets (0=Full, 1=Student, 2=Senior)
                        // Check if issuing station matches validating station
                        if (issuingStation.ToUpper() != request.ValidatingStation.ToUpper())
                        {
                            transaction.Rollback();
                            return BadRequest($"Ticket issued at {issuingStation} cannot be used for entry at {request.ValidatingStation}");
                        }
                        break;
                }

                // Update ticket state to "Entered Station" (2)
                using var updateCmd = new SqlCommand(@"
                    UPDATE Tickets 
                    SET TicketState = 2
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                updateCmd.Parameters.AddWithValue("@ticketNumber", request.TicketNumber);
                updateCmd.ExecuteNonQuery();

                transaction.Commit();

                return Ok(new
                {
                    ticketNumber = request.TicketNumber,
                    status = "entry_validated",
                    validationTime = DateTime.UtcNow,
                    ticketType = ticketType,
                    issuingStation = issuingStation,
                    validatingStation = request.ValidatingStation
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Entry ticket validation failed: {ex.Message}");
            }
        }

        // Validate ticket at exit faregate (REQUIRES ValidateTickets permission)
        [HttpPost("validateticketatexit")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ValidateTickets)]
        public IActionResult ValidateTicketAtExit([FromBody] ValidateTicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // ValidatingStation is required for exit validation
            if (string.IsNullOrEmpty(request.ValidatingStation))
            {
                return BadRequest("Validating station is required for exit validation");
            }

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                // Get ticket information
                using var ticketCmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, IssueDateTime, TicketType, TicketState
                    FROM Tickets 
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                ticketCmd.Parameters.AddWithValue("@ticketNumber", request.TicketNumber);

                using var reader = ticketCmd.ExecuteReader();
                if (!reader.Read())
                {
                    transaction.Rollback();
                    return BadRequest("Ticket not found");
                }

                var ticketType = reader.GetByte("TicketType");
                var ticketState = reader.GetByte("TicketState");
                var issuingStation = reader.GetString("IssuingStation");
                var issueDateTime = reader.GetDateTime("IssueDateTime");
                var valueCents = reader.GetInt32("ValueCents");

                reader.Close();

                // Check ticket state (allow 1=Paid or 2=Entered)
                if (ticketState != 1 && ticketState != 2)
                {
                    transaction.Rollback();
                    return BadRequest("Ticket is not in valid state for exit");
                }

                int newTicketState = 3; // Default: Exited Station

                // Handle different ticket types
                switch (ticketType)
                {
                    case 3: // Free Exit ticket
                        // Free exit tickets can only be used at issuing station
                        if (issuingStation.ToUpper() != request.ValidatingStation.ToUpper())
                        {
                            transaction.Rollback();
                            return BadRequest($"Free exit ticket issued at {issuingStation} can only be used at {issuingStation}");
                        }
                        break;

                    case 4: // Day Pass
                        // Check if ticket is for current day
                        var ticketDate = issueDateTime.Date;
                        var currentDate = DateTime.Now.Date;
                        
                        if (ticketDate != currentDate)
                        {
                            transaction.Rollback();
                            return BadRequest("Day pass is not valid for today");
                        }
                        
                        // Day pass: set state back to 1 (reusable)
                        newTicketState = 1;
                        break;

                    default: // Regular tickets (0=Full, 1=Student, 2=Senior)
                        // Calculate required fare from issuing station to exit station
                        var fareInfo = GetFareInfoInternal(connection, transaction, issuingStation, request.ValidatingStation);
                        if (fareInfo == null)
                        {
                            transaction.Rollback();
                            return BadRequest($"No fare rule found from {issuingStation} to {request.ValidatingStation}");
                        }

                        int requiredFare = fareInfo.Value.FareCents;

                        // Apply discounts based on ticket type
                        switch (ticketType)
                        {
                            case 1: // Student - 25% discount
                                requiredFare = (int)(requiredFare * 0.75);
                                break;
                            case 2: // Senior - 50% discount
                                requiredFare = (int)(requiredFare * 0.50);
                                break;
                            // case 0: Full fare - no discount
                        }

                        // Check if ticket has sufficient value
                        if (valueCents < requiredFare)
                        {
                            transaction.Rollback();
                            return BadRequest($"Insufficient fare: ticket value {valueCents} cents, required {requiredFare} cents");
                        }
                        break;
                }

                // Update ticket state
                using var updateCmd = new SqlCommand(@"
                    UPDATE Tickets 
                    SET TicketState = @newState
                    WHERE TicketNumber = @ticketNumber", connection, transaction);

                updateCmd.Parameters.AddWithValue("@newState", newTicketState);
                updateCmd.Parameters.AddWithValue("@ticketNumber", request.TicketNumber);
                updateCmd.ExecuteNonQuery();

                transaction.Commit();

                return Ok(new
                {
                    ticketNumber = request.TicketNumber,
                    status = newTicketState == 1 ? "exit_validated_reusable" : "exit_validated",
                    validationTime = DateTime.UtcNow,
                    ticketType = ticketType,
                    issuingStation = issuingStation,
                    validatingStation = request.ValidatingStation,
                    newTicketState = newTicketState
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Exit ticket validation failed: {ex.Message}");
            }
        }

        // Get the current day's signing keys (3 AM to 3 AM next day)
        [HttpGet("currentdaykeys")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.SystemAdmin)]
        public IActionResult GetCurrentDaySigningKeys()
        {
            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                // Determine the correct key window
                var now = DateTime.UtcNow;
                var tz = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneId);
                var localNow = TimeZoneInfo.ConvertTimeFromUtc(now, tz);

                // Calculate 3 AM boundaries
                DateTime start, end;
                if (localNow.Hour < 3)
                {
                    // Between midnight and 3 AM: use previous day's 3 AM to current day's 3 AM
                    var prevDay = localNow.Date.AddDays(-1);
                    start = prevDay.AddHours(3);
                    end = localNow.Date.AddHours(3);
                }
                else
                {
                    // Otherwise: use current day's 3 AM to next day's 3 AM
                    start = localNow.Date.AddHours(3);
                    end = localNow.Date.AddDays(1).AddHours(3);
                }

                // Query for the key created after start but before end
                using var cmd = new SqlCommand(@"
                    SELECT TOP 1 KeyVersion, KeyCreated, PublicKey, XorKey
                    FROM SigningKeys
                    WHERE KeyCreated >= @start AND KeyCreated < @end
                    ORDER BY KeyCreated DESC", connection);

                cmd.Parameters.AddWithValue("@start", start);
                cmd.Parameters.AddWithValue("@end", end);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return NotFound("No signing key found for the current day window.");
                }

                var keyInfo = new
                {
                    KeyVersion = reader.GetInt32(reader.GetOrdinal("KeyVersion")),
                    KeyCreated = reader.GetDateTime(reader.GetOrdinal("KeyCreated")),
                    PublicKey = reader.GetString(reader.GetOrdinal("PublicKey")),
                    XorKey = Convert.ToBase64String((byte[])reader["XorKey"])
                };

                return Ok(keyInfo);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to get current day's signing keys: {ex.Message}");
            }
        }

        // Helper method to get fare information internally (shared between GetFare and validation methods)
        [NonAction]
        private FareInfo? GetFareInfoInternal(SqlConnection connection, SqlTransaction? transaction, string fromStation, string toStation)
        {
            try
            {
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
                      AND ts.IsActive = 1", connection, transaction);

                cmd.Parameters.AddWithValue("@fromStation", fromStation.ToUpper());
                cmd.Parameters.AddWithValue("@toStation", toStation.ToUpper());

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return null;
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
                    WHERE FromZone = @fromZone AND ToZone = @toZone", connection, transaction);

                fareCmd.Parameters.AddWithValue("@fromZone", fromZone);
                fareCmd.Parameters.AddWithValue("@toZone", toZone);

                var fareResult = fareCmd.ExecuteScalar();
                if (fareResult == null)
                {
                    return null;
                }

                var fareCents = Convert.ToInt32(fareResult);

                return new FareInfo
                {
                    FromStation = fromStation.ToUpper(),
                    ToStation = toStation.ToUpper(),
                    FromZone = fromZone,
                    ToZone = toZone,
                    FareCents = fareCents,
                    FromStationName = fromName,
                    ToStationName = toName
                };
            }
            catch
            {
                return null;
            }
        }

        // Helper method to save ticket to database
        [NonAction]
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

        // Helper method to get day pass price for internal use
        [NonAction]
        private int GetDayPassPriceCents()
        {
            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var cmd = new SqlCommand(@"
                    SELECT SettingValue 
                    FROM SystemIntegerVariables 
                    WHERE SettingKey = 'DayPassPriceCents'", connection);

                var result = cmd.ExecuteScalar();
                if (result != null)
                {
                    return (int)result;
                }

                // Default fallback price if not configured (¥10.00)
                return 1000;
            }
            catch
            {
                // Default fallback price on error
                return 1000;
            }
        }

        // Get current day pass price (REQUIRES ViewFares permission)
        [HttpGet("daypassprice")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ViewFares)]
        public IActionResult GetDayPassPrice()
        {
            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var cmd = new SqlCommand(@"
                    SELECT SettingValue, LastUpdated 
                    FROM SystemIntegerVariables 
                    WHERE SettingKey = 'DayPassPriceCents'", connection);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return NotFound("Day pass price not configured");
                }

                int priceCents = reader.GetInt32("SettingValue");
                DateTime lastUpdated = reader.GetDateTime("LastUpdated");

                return Ok(new
                {
                    dayPassPriceCents = priceCents,
                    dayPassPriceYuan = priceCents / 100.0m,
                    lastUpdated = lastUpdated
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Day pass price lookup failed: {ex.Message}");
            }
        }

        // Update day pass price (REQUIRES SystemAdmin permission)
        [HttpPost("daypassprice")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.SystemAdmin)]
        public IActionResult UpdateDayPassPrice([FromBody] UpdateDayPassPriceRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var cmd = new SqlCommand(@"
                    UPDATE SystemIntegerVariables 
                    SET SettingValue = @newPrice, 
                        LastUpdated = GETUTCDATE(),
                        UpdatedBy = @updatedBy
                    WHERE SettingKey = 'DayPassPriceCents'", connection);

                cmd.Parameters.AddWithValue("@newPrice", request.PriceCents);
                cmd.Parameters.AddWithValue("@updatedBy", GetUsername());

                int rowsAffected = cmd.ExecuteNonQuery();
                if (rowsAffected == 0)
                {
                    return NotFound("Day pass price setting not found");
                }

                return Ok(new
                {
                    message = "Day pass price updated successfully",
                    newPriceCents = request.PriceCents,
                    newPriceYuan = request.PriceCents / 100.0m,
                    updatedBy = GetUsername(),
                    updatedAt = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Day pass price update failed: {ex.Message}");
            }
        }

        // Get user's permission information (renamed method to avoid conflict)
        [HttpGet("permissions")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        public IActionResult GetCurrentUserPermissions()
        {
            var permissions = GetUserPermissions(); // This calls the base class method
            var permissionNames = PermissionHelper.GetPermissionNames(permissions);

            return Ok(new
            {
                username = GetUsername(),
                userId = GetUserId(),
                permissionValue = permissions,
                permissions = permissionNames,
                canViewStations = HasPermission(ApiPermissions.ViewStations),
                canViewFares = HasPermission(ApiPermissions.ViewFares),
                canIssueFullFare = HasPermission(ApiPermissions.IssueFullFareTickets),
                canIssueStudent = HasPermission(ApiPermissions.IssueStudentTickets),
                canIssueSenior = HasPermission(ApiPermissions.IssueSeniorTickets),
                canIssueFree = HasPermission(ApiPermissions.IssueFreeEntryTickets),
                canIssueDayPass = HasPermission(ApiPermissions.IssueDayPassTickets),
                canReissue = HasPermission(ApiPermissions.ReissueTickets),
                canViewTickets = HasPermission(ApiPermissions.ViewTickets),
                canValidateTickets = HasPermission(ApiPermissions.ValidateTickets),
                canChangePassword = HasPermission(ApiPermissions.ChangePassword),
                canIssueInvoices = HasPermission(ApiPermissions.IssueInvoices),
                canRefundTickets = HasPermission(ApiPermissions.RefundTickets),
                isSystemAdmin = HasPermission(ApiPermissions.SystemAdmin)
            });
        }

        // Get all stations (REQUIRES ViewStations permission)
        [HttpGet("stations")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ViewStations)]
        public IActionResult GetAllStations()
        {
            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var cmd = new SqlCommand(@"
                    SELECT 
                        StationCode,
                        EnglishStationName,
                        ChineseStationName,
                        ZoneID,
                        IsActive
                    FROM Stations 
                    ORDER BY StationCode", connection);

                var stations = new List<StationInfo>();

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var stationInfo = new StationInfo
                    {
                        StationCode = reader.GetString("StationCode"),
                        EnglishName = reader.GetString("EnglishStationName"),
                        ChineseName = reader.GetString("ChineseStationName"),
                        ZoneId = reader.GetInt32("ZoneID"),
                        IsActive = reader.GetBoolean("IsActive")
                    };
                    stations.Add(stationInfo);
                }

                return Ok(stations);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Station list retrieval failed: {ex.Message}");
            }
        }

        // Issue debug ticket (only available in debug mode)
        [HttpGet("issuedebugticket")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        public IActionResult IssueDebugTicket()
        {
            if (!_debugMode)
            {
                return StatusCode(403, "Debug mode is disabled");
            }

            try
            {
                var ticketData = IssueTicketInternal(999, "DBG", 255); // Type 255 = Debug
                return Ok(ticketData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Debug ticket issuance failed: {ex.Message}");
            }
        }

        // Change own password (REQUIRES ChangePassword permission)
        [HttpPost("changepassword")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ChangePassword)]
        public IActionResult ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var userId = GetUserId();
                var username = GetUsername();
        
                // CRITICAL: Verify current password before changing
                var currentPasswordValid = ApiUserManager.VerifyPasswordAsync(username, request.CurrentPassword).Result;
                if (!currentPasswordValid)
                {
                    return BadRequest("Current password is incorrect");
                }
        
                // Only proceed if current password is valid
                var success = ApiUserManager.UpdatePasswordAsync(userId, request.NewPassword).Result;
        
                if (success)
                {
                    return Ok(new { message = "Password changed successfully" });
                }
                else
                {
                    return BadRequest("Failed to change password");
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Password change failed: {ex.Message}");
            }
        }
    }

    public class StationRequest
    {
        [Required(ErrorMessage = "Station code is required")]
        [StringLength(3, MinimumLength = 3, ErrorMessage = "Station code must be exactly 3 characters")]
        [RegularExpression(@"^[A-Za-z]+$", ErrorMessage = "Station code must contain only letters")]
        public required string StationCode { get; set; }
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
        [Range(0, 100000, ErrorMessage = "Value must be between 0 and 100000 cents")]
        public required int ValueCents { get; set; }
    }

    public class ReissueTicketRequest : TicketRequest
    {
        [Required(ErrorMessage = "Original ticket number is required")]
        public required string OriginalTicketNumber { get; set; }
    }

    public class ValidateTicketRequest
    {
        [Required(ErrorMessage = "Ticket number is required")]
        public required string TicketNumber { get; set; }

        [StringLength(3, MinimumLength = 3, ErrorMessage = "Station code must be 3 characters")]
        [RegularExpression(@"^[A-Z]+$", ErrorMessage = "Station code must be uppercase letters")]
        public string? ValidatingStation { get; set; }
    }

    public class ChangePasswordRequest
    {
        [Required(ErrorMessage = "Current password is required")]
        public required string CurrentPassword { get; set; }

        [Required(ErrorMessage = "New password is required")]
        [MinLength(8, ErrorMessage = "New password must be at least 8 characters")]
        public required string NewPassword { get; set; }
    }

    public class UpdateDayPassPriceRequest
    {
        [Required(ErrorMessage = "Price in cents is required")]
        [Range(0, 100000, ErrorMessage = "Price must be between 0 and 100000 cents")]
        public required int PriceCents { get; set; }
    }

    public class DayPassTicketRequest
    {
        [Required(ErrorMessage = "Issuing station is required")]
        [StringLength(3, MinimumLength = 3, ErrorMessage = "Station code must be 3 characters")]
        [RegularExpression(@"^[A-Z]+$", ErrorMessage = "Station code must be uppercase letters")]
        public required string IssuingStation { get; set; }
    }

    public class IssueInvoiceRequest
    {
        [Required(ErrorMessage = "Ticket input is required")]
        public required string TicketInput { get; set; }
    }

    public class RefundTicketRequest
    {
        [Required(ErrorMessage = "Ticket input is required")]
        public required string TicketInput { get; set; }
    }

    public class GetTicketInfoRequest
    {
        [Required(ErrorMessage = "Ticket input is required")]
        public required string TicketInput { get; set; }
    }
}