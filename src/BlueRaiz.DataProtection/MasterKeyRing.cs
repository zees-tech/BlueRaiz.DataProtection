using System.Security.Cryptography;
using System.Text;

namespace BlueRaiz.DataProtection;

// The master keys, as AES-256-GCM keys derived from the configured secrets. Each stored row records which one
// encrypted it (by Id), so the current key encrypts and any configured key decrypts.
internal sealed class MasterKeyRing
{
    public const int MinimumLength = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("BlueRaiz.DataProtection/v1");

    private readonly IReadOnlyList<(string Id, byte[] Key)> keys;

    public MasterKeyRing(string current, IEnumerable<string> previous)
    {
        keys = previous.Prepend(current).Select(secret => secret.Trim()).Distinct(StringComparer.Ordinal).Select(Derive).ToList();
    }

    public string CurrentId => keys[0].Id;

    public bool Knows(string id) => keys.Any(k => k.Id == id);

    // nonce | tag | ciphertext. The associated data binds the payload to its row, so rows can't be swapped.
    public byte[] Encrypt(byte[] plaintext, string associatedData)
    {
        var payload = new byte[NonceSize + TagSize + plaintext.Length];
        var nonce = payload.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(keys[0].Key, TagSize);
        aes.Encrypt(nonce, plaintext, payload.AsSpan(NonceSize + TagSize), payload.AsSpan(NonceSize, TagSize), Encoding.UTF8.GetBytes(associatedData));
        return payload;
    }

    // Null when the payload wasn't made by that key for that row.
    public byte[]? Decrypt(string id, byte[] payload, string associatedData)
    {
        var key = keys.FirstOrDefault(k => k.Id == id).Key;
        if (key is null || payload.Length < NonceSize + TagSize) return null;

        var plaintext = new byte[payload.Length - NonceSize - TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(payload.AsSpan(0, NonceSize), payload.AsSpan(NonceSize + TagSize), payload.AsSpan(NonceSize, TagSize), plaintext,
                Encoding.UTF8.GetBytes(associatedData));
            return plaintext;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static (string Id, byte[] Key) Derive(string secret)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(secret), 32, salt: null, info: Info);
        // Identifies the key without revealing it: a hash of the derived key, never of the secret alone.
        var id = Convert.ToHexString(SHA256.HashData(key))[..16].ToLowerInvariant();
        return (id, key);
    }
}
