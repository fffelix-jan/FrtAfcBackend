using DotNetEnv;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;

namespace FrtAfcBackend
{
    /// <summary>
    /// Bitwise permission flags for FRT AFC API access control
    /// </summary>
    [Flags]
    public enum ApiPermissions : int
    {
        None = 0,                           // 0x0000 - No permissions
        
        // Basic permissions
        ViewStations = 1 << 0,              // 0x0001 - View station information
        ViewFares = 1 << 1,                 // 0x0002 - View fare information
        IssueFullFareTickets = 1 << 2,      // 0x0004 - Issue full fare tickets
        IssueStudentTickets = 1 << 3,       // 0x0008 - Issue student tickets
        IssueSeniorTickets = 1 << 4,        // 0x0010 - Issue senior tickets
        IssueFreeEntryTickets = 1 << 5,     // 0x0020 - Issue free entry tickets
        IssueDayPassTickets = 1 << 6,       // 0x0040 - Issue day pass tickets
        ReissueTickets = 1 << 7,            // 0x0080 - Reissue damaged tickets
        ViewTickets = 1 << 8,               // 0x0100 - View ticket information
        ValidateTickets = 1 << 9,           // 0x0200 - Validate tickets at gates (i.e. mark them as used)

        // User permissions
        ChangePassword = 1 << 10,           // 0x0400 - Change own password

        // Additional permissions
        IssueInvoices = 1 << 11,          // 0x0800 - Issue invoices
        RefundTickets = 1 << 12,          // 0x1000 - Refund tickets

        // System administration - ALL PERMISSIONS
        SystemAdmin = int.MaxValue,         // 0x7FFFFFFF - Full system administrator (ALL FLAGS SET)
        
        // Convenience combinations
        BasicUser = ViewStations | ViewFares | ViewTickets,                                    // Standard read-only user
        TicketOperator = BasicUser | IssueFullFareTickets | IssueStudentTickets | IssueSeniorTickets | IssueFreeEntryTickets | IssueDayPassTickets | ReissueTickets | ViewTickets | ValidateTickets | ChangePassword | IssueInvoices | RefundTickets,                // Ticket sales operator
        TicketVendingMachine = BasicUser | IssueFullFareTickets,
        Faregate = BasicUser | ValidateTickets,
    }

    public static class PermissionHelper
    {
        /// <summary>
        /// Checks if user has the required permission
        /// </summary>
        public static bool HasPermission(int userPermissions, ApiPermissions requiredPermission)
        {
            return (userPermissions & (int)requiredPermission) == (int)requiredPermission;
        }

        /// <summary>
        /// Checks if user has any of the specified permissions
        /// </summary>
        public static bool HasAnyPermission(int userPermissions, params ApiPermissions[] permissions)
        {
            return permissions.Any(p => HasPermission(userPermissions, p));
        }

        /// <summary>
        /// Gets human-readable permission names
        /// </summary>
        public static List<string> GetPermissionNames(int permissions)
        {
            var names = new List<string>();
            foreach (ApiPermissions permission in Enum.GetValues<ApiPermissions>())
            {
                if (permission != ApiPermissions.None && 
                    permission != ApiPermissions.SystemAdmin && // Don't show SystemAdmin in individual permissions
                    HasPermission(permissions, permission))
                {
                    names.Add(permission.ToString());
                }
            }
            
            // Show SystemAdmin if user has it
            if (HasPermission(permissions, ApiPermissions.SystemAdmin))
            {
                names.Add("SystemAdmin");
            }
            
            return names;
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            // Load the environment variables from the .env file
            Env.Load();

            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllers();

            // Add Basic Authentication with database validation
            builder.Services.AddAuthentication("BasicAuthentication")
                .AddScheme<AuthenticationSchemeOptions, DatabaseBasicAuthenticationHandler>("BasicAuthentication", null);

            builder.Services.AddAuthorization();

            var app = builder.Build();

            // Configure the HTTP request pipeline.

            // DUAL HTTP/HTTPS MODE (Current Configuration)
            // This allows both HTTP and HTTPS endpoints to work simultaneously
            // HTTP: http://0.0.0.0:5281 (configured in launchSettings.json)
            // HTTPS: https://0.0.0.0:7184 (configured in launchSettings.json)
            
            // HTTPS redirection is commented out to allow both protocols
            // app.UseHttpsRedirection();

            /* 
            TO SWITCH TO HTTPS-ONLY MODE:
            1. Uncomment the line above: app.UseHttpsRedirection();
            2. Update launchSettings.json to remove HTTP URLs:
               - Change "applicationUrl": "https://0.0.0.0:7184;http://0.0.0.0:5281"
               - To: "applicationUrl": "https://0.0.0.0:7184"
            3. Ensure all client applications use HTTPS URLs
            4. Install SSL certificates on all client machines (see certificate installation guide)
            
            HTTPS-only benefits:
            - All traffic encrypted
            - Better security for API keys and sensitive data
            - Required for production environments
            
            Current dual-mode benefits:
            - Easy testing without certificate issues
            - Compatible with clients that don't have certificates installed
            - Gradual migration path
            */

            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();

            app.Run();
        }
    }

    public class DatabaseBasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly string? _connectionString = Environment.GetEnvironmentVariable("SQLSERVER_CONNECTION_STRING");

        public DatabaseBasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, 
            ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // Check if Authorization header exists
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Missing Authorization Header");

            try
            {
                var authHeader = Request.Headers["Authorization"].ToString();
                if (!authHeader.StartsWith("Basic "))
                    return AuthenticateResult.Fail("Invalid Authorization Header");

                // Decode the Base64 encoded username:password
                var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
                var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
                var credentials = decodedCredentials.Split(':', 2);

                if (credentials.Length != 2)
                    return AuthenticateResult.Fail("Invalid Authorization Header Format");

                var username = credentials[0];
                var password = credentials[1];

                // Validate credentials against database
                var user = await ValidateUserCredentialsAsync(username, password);
                if (user == null)
                    return AuthenticateResult.Fail("Invalid Username or Password");

                // Create claims and identity
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, "FareApiUser"),
                    new Claim("UserPermissions", user.UserPermissions.ToString()),
                    new Claim("UserId", user.Id.ToString())
                };

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                // Update last login time
                await UpdateLastLoginAsync(user.Id);

                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Authentication error");
                return AuthenticateResult.Fail("Authentication failed");
            }
        }

        private async Task<ApiUser?> ValidateUserCredentialsAsync(string username, string password)
        {
            if (string.IsNullOrEmpty(_connectionString))
                return null;

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                using var cmd = new SqlCommand(@"
                    SELECT Id, Username, PasswordHash, Salt, UserPermissions, IsActive, UserDescription
                    FROM ApiUsers 
                    WHERE Username = @username AND IsActive = 1", connection);

                cmd.Parameters.AddWithValue("@username", username);

                using var reader = await cmd.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                    return null;

                var user = new ApiUser
                {
                    Id = reader.GetInt32(reader.GetOrdinal("Id")),
                    Username = reader.GetString(reader.GetOrdinal("Username")),
                    PasswordHash = reader.GetString(reader.GetOrdinal("PasswordHash")),
                    Salt = reader.GetString(reader.GetOrdinal("Salt")),
                    UserPermissions = reader.GetInt32(reader.GetOrdinal("UserPermissions")),
                    IsActive = reader.GetBoolean(reader.GetOrdinal("IsActive")),
                    UserDescription = reader.IsDBNull(reader.GetOrdinal("UserDescription")) 
                        ? null 
                        : reader.GetString(reader.GetOrdinal("UserDescription"))
                };

                // Verify password
                var computedHash = HashPassword(password, user.Salt);
                if (computedHash != user.PasswordHash)
                    return null;

                return user;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Database error during authentication");
                return null;
            }
        }

        private async Task UpdateLastLoginAsync(int userId)
        {
            if (string.IsNullOrEmpty(_connectionString))
                return;

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                using var cmd = new SqlCommand(@"
                    UPDATE ApiUsers 
                    SET LastLoginDateTime = GETUTCDATE() 
                    WHERE Id = @userId", connection);

                cmd.Parameters.AddWithValue("@userId", userId);
                await cmd.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed to update last login time for user {UserId}", userId);
            }
        }

        private static string HashPassword(string password, string salt)
        {
            // Use PBKDF2 with SHA256 for secure password hashing
            using var pbkdf2 = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), 10000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(64); // 64 bytes = 512 bits
            return Convert.ToBase64String(hash);
        }
    }

    public class ApiUser
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public int UserPermissions { get; set; }
        public bool IsActive { get; set; }
        public string? UserDescription { get; set; }
    }
}
