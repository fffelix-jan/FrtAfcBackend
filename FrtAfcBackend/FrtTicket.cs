using System;
using System.Security.Cryptography;
using System.Text;
using K4os.Compression.LZ4;
using Microsoft.Data.SqlClient;

/// <summary>
/// FrtTicket 0.1.1
/// Provides methods for encoding and decoding FRT (Falloway Rapid Transit) tickets
/// with cryptographic signatures and obfuscation for QR code generation.
/// </summary>
public static class FrtTicket
{
    // Constants
    public static readonly byte[] MagicBytes = Encoding.UTF8.GetBytes("FRT"); // 3-byte header
    public const string TimeZoneId = "China Standard Time"; // Change to your metro's timezone

    public static byte[] XorObfuscate(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }

    /// <summary>
    /// Encodes ticket data into a secure, obfuscated string suitable for QR code generation.
    /// </summary>
    /// <param name="ticketNumber">Unique identifier for the ticket (12-18 digits recommended).</param>
    /// <param name="valueCents">Ticket value in cents (must be non-negative).</param>
    /// <param name="issuingStation">3-letter station code where the ticket was issued.</param>
    /// <param name="issueDateTime">Exact timestamp of ticket issuance.</param>
    /// <param name="ticketType">
    /// Ticket type identifier:
    /// <list type="bullet">
    ///   <item><description>0 - Full Fare</description></item>
    ///   <item><description>1 - Student</description></item>
    ///   <item><description>2 - Senior</description></item>
    ///   <item><description>3 - Free Exit</description></item>
    ///   <item><description>4 - Day Pass</description></item>
    ///   <item><description>255 - Debug</description></item>
    /// </list>
    /// </param>
    /// <param name="signingKey">ECDsa private key for cryptographic signing.</param>
    /// <param name="xorObfuscatorKey">
    /// Secret key for XOR obfuscation (minimum 16 bytes recommended).
    /// Must match the key used for decoding.
    /// </param>
    /// <returns>
    /// URL-safe Base64 encoded string containing:
    /// <list type="number">
    ///   <item><description>3-byte "FRT" magic header</description></item>
    ///   <item><description>LZ4-compressed ticket data</description></item>
    ///   <item><description>ECDSA signature (64 bytes for P-256)</description></item>
    /// </list>
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if signingKey or xorObfuscatorKey is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if issuingStation is not 3 characters or valueCents is negative.
    /// </exception>
    /// <example>
    /// <code>
    /// using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    /// byte[] xorKey = new byte[32]; // 256-bit key
    /// RandomNumberGenerator.Fill(xorKey);
    /// 
    /// string ticket = FrtTicket.EncodeTicket(
    ///     ticketNumber: 12345678901234,
    ///     valueCents: 1250,
    ///     issuingStation: "CTR",
    ///     issueDateTime: DateTime.UtcNow,
    ///     ticketType: 0,
    ///     signingKey: key,
    ///     xorObfuscatorKey: xorKey);
    /// </code>
    /// </example>
    public static string EncodeTicket(
        long ticketNumber,
        int valueCents,
        string issuingStation,
        DateTime issueDateTime,
        byte ticketType,
        ECDsa signingKey,
        byte[] xorObfuscatorKey)
    {
        // 1. Create the ticket string
        string ticketString =
            $"{ticketNumber}|{valueCents}|{issuingStation}|{issueDateTime:yyyyMMddHHmmss}|{ticketType}";

        // 2. Compress the ticket data
        byte[] dataBytes = Encoding.UTF8.GetBytes(ticketString);
        byte[] compressed = LZ4Pickler.Pickle(dataBytes, LZ4Level.L00_FAST);

        // 3. Add magic bytes header
        byte[] dataWithHeader = new byte[MagicBytes.Length + compressed.Length];
        Buffer.BlockCopy(MagicBytes, 0, dataWithHeader, 0, MagicBytes.Length);
        Buffer.BlockCopy(compressed, 0, dataWithHeader, MagicBytes.Length, compressed.Length);

        // 4. Sign the data (including magic bytes)
        byte[] signature = signingKey.SignData(dataWithHeader, HashAlgorithmName.SHA256);

        // 5. Combine header + compressed data + signature
        byte[] combined = new byte[dataWithHeader.Length + signature.Length];
        Buffer.BlockCopy(dataWithHeader, 0, combined, 0, dataWithHeader.Length);
        Buffer.BlockCopy(signature, 0, combined, dataWithHeader.Length, signature.Length);

        // 6. XOR obfuscate
        byte[] obfuscated = XorObfuscate(combined, xorObfuscatorKey);

        // 7. Convert to URL-safe Base64
        return Convert.ToBase64String(obfuscated)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Decodes and validates an FRT ticket string, verifying both the XOR obfuscation key
    /// and cryptographic signature.
    /// </summary>
    /// <param name="encodedTicket">
    /// URL-safe Base64 string produced by <see cref="EncodeTicket"/>.
    /// </param>
    /// <param name="signingKey">ECDsa public key for signature verification.</param>
    /// <param name="xorObfuscatorKey">
    /// Secret XOR key that must match the one used during encoding.
    /// </param>
    /// <param name="ticketNumber">Output: Decoded ticket number.</param>
    /// <param name="valueCents">Output: Ticket value in cents.</param>
    /// <param name="issuingStation">Output: 3-letter issuing station code.</param>
    /// <param name="issueDateTime">Output: Ticket issuance timestamp.</param>
    /// <param name="ticketType">Output: Numeric ticket type identifier.</param>
    /// <returns>
    /// True if the ticket is valid (correct XOR key, valid signature, and properly formatted),
    /// false otherwise. Output parameters are only valid when returning true.
    /// </returns>
    /// <remarks>
    /// The decoding process performs these validation steps:
    /// <list type="number">
    ///   <item><description>Base64 URL decoding</description></item>
    ///   <item><description>XOR deobfuscation with magic bytes verification</description></item>
    ///   <item><description>ECDSA signature verification</description></item>
    ///   <item><description>LZ4 decompression</description></item>
    ///   <item><description>Data format validation</description></item>
    /// </list>
    /// </remarks>
    /// <example>
    /// <code>
    /// bool valid = FrtTicket.TryDecodeTicket(
    ///     encodedTicket: qrCodeData,
    ///     signingKey: publicKey,
    ///     xorObfuscatorKey: xorKey,
    ///     out long number,
    ///     out int value,
    ///     out string station,
    ///     out DateTime issued,
    ///     out byte type);
    /// 
    /// if (valid) { /* Process ticket */ }
    /// </code>
    /// </example>
    public static bool TryDecodeTicket(
        string encodedTicket,
        ECDsa signingKey,
        byte[] xorObfuscatorKey,
        out long ticketNumber,
        out int valueCents,
        out string issuingStation,
        out DateTime issueDateTime,
        out byte ticketType)
    {
        ticketNumber = 0;
        valueCents = 0;
        issuingStation = string.Empty;
        issueDateTime = DateTime.MinValue;
        ticketType = 0;

        try
        {
            // 1. Restore Base64
            string padded = encodedTicket
                .Replace('-', '+')
                .Replace('_', '/')
                .PadRight(encodedTicket.Length + (4 - encodedTicket.Length % 4) % 4, '=');

            // 2. Convert from Base64
            byte[] obfuscated = Convert.FromBase64String(padded);

            // 3. De-XOR the ticket
            byte[] combined = XorObfuscate(obfuscated, xorObfuscatorKey);

            // 4. Extract signature (last 64 bytes for P-256)
            int dataLength = combined.Length - 64;
            if (dataLength < MagicBytes.Length) return false; // Not enough data for magic bytes

            byte[] signedData = new byte[dataLength];
            byte[] signature = new byte[64];
            Buffer.BlockCopy(combined, 0, signedData, 0, dataLength);
            Buffer.BlockCopy(combined, dataLength, signature, 0, 64);

            // 5. Verify magic bytes (XOR key check)
            for (int i = 0; i < MagicBytes.Length; i++)
            {
                if (signedData[i] != MagicBytes[i])
                {
                    return false; // XOR key verification failed
                }
            }

            // 6. Verify cryptographic signature
            if (!signingKey.VerifyData(signedData, signature, HashAlgorithmName.SHA256))
                return false;

            // 7. Extract compressed data (after magic bytes)
            byte[] compressed = new byte[dataLength - MagicBytes.Length];
            Buffer.BlockCopy(signedData, MagicBytes.Length, compressed, 0, compressed.Length);

            // 8. Decompress
            byte[] dataBytes = LZ4Pickler.Unpickle(compressed);
            string ticketData = Encoding.UTF8.GetString(dataBytes);

            // 9. Parse
            string[] parts = ticketData.Split('|');
            if (parts.Length != 5) return false;

            // Parse fields
            ticketNumber = long.Parse(parts[0]);
            valueCents = int.Parse(parts[1]);
            issuingStation = parts[2];
            issueDateTime = DateTime.ParseExact(parts[3], "yyyyMMddHHmmss", null);
            ticketType = byte.Parse(parts[4]);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static (ECDsa signingKey, byte[] xorKey) GetCurrentKeys(SqlConnection conn, SqlTransaction tx)
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

    public static (ECDsa? signingKey, byte[]? xorKey) TryGetValidKeys(SqlConnection conn, SqlTransaction tx)
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

    public static (ECDsa signingKey, byte[] xorKey) GenerateNewKeys(SqlConnection conn, SqlTransaction tx)
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

    public static int GetNextKeyVersion(SqlConnection conn, SqlTransaction tx)
    {
        using var cmd = new SqlCommand(
            "SELECT ISNULL(MAX(KeyVersion), 0) + 1 FROM SigningKeys",
            conn, tx);
        return Convert.ToInt32(cmd.ExecuteScalar());
    }
}