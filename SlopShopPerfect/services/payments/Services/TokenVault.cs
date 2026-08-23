using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SlopShop.Payments.Services;

/// <summary>
/// Envelope encryption for payment instrument references.
/// </summary>
/// <remarks>
/// What is stored is the processor-issued reference for a saved instrument,
/// encrypted at rest with AES-256-GCM. The key version travels in the
/// authenticated additional data alongside the customer id.
/// </remarks>
public sealed class TokenVault : IDisposable
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int KeyBytes = 32;

    private readonly AesGcm _aes;
    private readonly int _keyVersion;

    /// <summary>
    /// Builds a vault from the key the deployment injects at start-up.
    /// </summary>
    public static TokenVault FromEnvironment()
    {
        string? hexKey = Environment.GetEnvironmentVariable("PAYMENTS_VAULT_KEY");
        string? version = Environment.GetEnvironmentVariable("PAYMENTS_VAULT_KEY_VERSION");

        if (string.IsNullOrWhiteSpace(hexKey))
        {
            throw new InvalidOperationException("PAYMENTS_VAULT_KEY is not configured");
        }
        if (!int.TryParse(version, out int parsedVersion) || parsedVersion < 1)
        {
            throw new InvalidOperationException("PAYMENTS_VAULT_KEY_VERSION is not configured");
        }

        byte[] key = Convert.FromHexString(hexKey);
        try
        {
            return new TokenVault(key, parsedVersion);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public TokenVault(ReadOnlySpan<byte> key, int keyVersion)
    {
        if (key.Length != KeyBytes)
        {
            throw new ArgumentException("vault key must be exactly 32 bytes", nameof(key));
        }
        _aes = new AesGcm(key, TagBytes);
        _keyVersion = keyVersion;
    }

    private byte[] AdditionalData(string customerId)
    {
        byte[] customer = Encoding.UTF8.GetBytes(customerId);
        byte[] aad = new byte[4 + customer.Length];
        BinaryPrimitives.WriteInt32BigEndian(aad.AsSpan(0, 4), _keyVersion);
        customer.CopyTo(aad.AsSpan(4));
        return aad;
    }

    /// <summary>
    /// Encrypts a processor reference. The returned blob is
    /// <c>version || nonce || tag || ciphertext</c>.
    /// </summary>
    public byte[] Seal(string processorReference, string customerId)
    {
        ArgumentException.ThrowIfNullOrEmpty(processorReference);
        ArgumentException.ThrowIfNullOrEmpty(customerId);

        byte[] plaintext = Encoding.UTF8.GetBytes(processorReference);
        byte[] sealedBlob = new byte[4 + NonceBytes + TagBytes + plaintext.Length];

        BinaryPrimitives.WriteInt32BigEndian(sealedBlob.AsSpan(0, 4), _keyVersion);
        Span<byte> nonce = sealedBlob.AsSpan(4, NonceBytes);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> tag = sealedBlob.AsSpan(4 + NonceBytes, TagBytes);
        Span<byte> ciphertext = sealedBlob.AsSpan(4 + NonceBytes + TagBytes);

        try
        {
            _aes.Encrypt(nonce, plaintext, ciphertext, tag, AdditionalData(customerId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }

        return sealedBlob;
    }

    /// <summary>
    /// Decrypts a blob produced by <see cref="Seal"/>.
    /// </summary>
    public string Open(ReadOnlySpan<byte> sealedBlob, string customerId)
    {
        ArgumentException.ThrowIfNullOrEmpty(customerId);

        if (sealedBlob.Length < 4 + NonceBytes + TagBytes)
        {
            throw new CryptographicException("sealed blob is truncated");
        }

        int version = BinaryPrimitives.ReadInt32BigEndian(sealedBlob[..4]);
        if (version != _keyVersion)
        {
            throw new CryptographicException("sealed blob was written under another key version");
        }

        ReadOnlySpan<byte> nonce = sealedBlob.Slice(4, NonceBytes);
        ReadOnlySpan<byte> tag = sealedBlob.Slice(4 + NonceBytes, TagBytes);
        ReadOnlySpan<byte> ciphertext = sealedBlob[(4 + NonceBytes + TagBytes)..];

        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            _aes.Decrypt(nonce, ciphertext, tag, plaintext, AdditionalData(customerId));
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void Dispose() => _aes.Dispose();
}
