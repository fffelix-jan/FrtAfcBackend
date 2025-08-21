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
        public IActionResult IssueDayPassTicket([FromBody] TicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var ticketData = IssueTicketInternal(request.ValueCents, request.IssuingStation!, 4); // Type 4 = Day Pass
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
                // TODO: Implement ticket lookup and validation logic
                // For now, issue a replacement ticket with the same details
                var ticketData = IssueTicketInternal(request.ValueCents, request.IssuingStation!, request.TicketType);
                return Ok(new { 
                    originalTicket = request.OriginalTicketNumber,
                    replacementTicket = ticketData 
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ticket reissuance failed: {ex.Message}");
            }
        }

        // View ticket information (REQUIRES ViewTickets permission)
        [HttpGet("ticket/{ticketNumber}")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ViewTickets)]
        public IActionResult GetTicketInfo(string ticketNumber)
        {
            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var cmd = new SqlCommand(@"
                    SELECT TicketNumber, ValueCents, IssuingStation, IssueDateTime, TicketType, TicketState
                    FROM Tickets 
                    WHERE TicketNumber = @ticketNumber", connection);

                cmd.Parameters.AddWithValue("@ticketNumber", ticketNumber);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    return NotFound($"Ticket '{ticketNumber}' not found");
                }

                var ticketInfo = new
                {
                    ticketNumber = reader.GetInt64("TicketNumber"),
                    valueCents = reader.GetInt32("ValueCents"),
                    issuingStation = reader.GetString("IssuingStation"),
                    issueDateTime = reader.GetDateTime("IssueDateTime"),
                    ticketType = reader.GetByte("TicketType"),
                    ticketState = reader.GetByte("TicketState")
                };

                return Ok(ticketInfo);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ticket lookup failed: {ex.Message}");
            }
        }

        // Validate ticket at faregate (REQUIRES ValidateTickets permission)
        [HttpPost("validateticket")]
        [Authorize(AuthenticationSchemes = "BasicAuthentication")]
        [RequirePermission(ApiPermissions.ValidateTickets)]
        public IActionResult ValidateTicket([FromBody] ValidateTicketRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                using var connection = new SqlConnection(_connectionString);
                connection.Open();

                using var transaction = connection.BeginTransaction();

                // Update ticket state to "Used"
                using var cmd = new SqlCommand(@"
                    UPDATE Tickets 
                    SET TicketState = 2, UsedDateTime = GETUTCDATE() 
                    WHERE TicketNumber = @ticketNumber AND TicketState = 1", connection, transaction);

                cmd.Parameters.AddWithValue("@ticketNumber", request.TicketNumber);

                var rowsAffected = cmd.ExecuteNonQuery();
                if (rowsAffected == 0)
                {
                    transaction.Rollback();
                    return BadRequest("Ticket not found or already used");
                }

                transaction.Commit();

                return Ok(new { 
                    ticketNumber = request.TicketNumber,
                    status = "validated",
                    validationTime = DateTime.UtcNow 
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Ticket validation failed: {ex.Message}");
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

        [Required(ErrorMessage = "Ticket type is required")]
        [Range(0, 255, ErrorMessage = "Ticket type must be between 0 and 255")]
        public required byte TicketType { get; set; }
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
}