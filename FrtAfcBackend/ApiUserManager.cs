using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

namespace FrtAfcBackend
{
    /// <summary>
    /// API User Manager - LIMITED TO PASSWORD UPDATES ONLY
    /// User creation/deletion is handled externally via direct SQL Server access
    /// User listing is restricted to DBA direct SQL access for security
    /// </summary>
    public static class ApiUserManager
    {
        private static readonly string? _connectionString = Environment.GetEnvironmentVariable("SQLSERVER_CONNECTION_STRING");

        /// <summary>
        /// Updates user password (for authenticated users changing their own password)
        /// </summary>
        /// <param name="userId">User ID to update</param>
        /// <param name="newPassword">New plain text password</param>
        /// <returns>True if successful</returns>
        public static async Task<bool> UpdatePasswordAsync(int userId, string newPassword)
        {
            if (string.IsNullOrEmpty(_connectionString))
                return false;

            var salt = GenerateSalt();
            var passwordHash = HashPassword(newPassword, salt);

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                using var cmd = new SqlCommand(@"
                    UPDATE ApiUsers 
                    SET PasswordHash = @passwordHash, Salt = @salt
                    WHERE Id = @userId AND IsActive = 1", connection);

                cmd.Parameters.AddWithValue("@userId", userId);
                cmd.Parameters.AddWithValue("@passwordHash", passwordHash);
                cmd.Parameters.AddWithValue("@salt", Convert.ToBase64String(salt));

                var rowsAffected = await cmd.ExecuteNonQueryAsync();
                return rowsAffected > 0;
            }
            catch
            {
                return false;
            }
        }

        private static byte[] GenerateSalt()
        {
            var salt = new byte[32]; // 256 bits
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return salt;
        }

        private static string HashPassword(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(64); // 64 bytes = 512 bits
            return Convert.ToBase64String(hash);
        }
    }
}