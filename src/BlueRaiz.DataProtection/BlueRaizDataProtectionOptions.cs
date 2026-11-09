using System.Text.RegularExpressions;

namespace BlueRaiz.DataProtection;

/// <summary>Where an app keeps its Data Protection keys, and the master key that encrypts them.</summary>
public sealed partial class BlueRaizDataProtectionOptions
{
    /// <summary>
    /// The app's Data Protection application name. Keep it the same for the app's whole life: data protected under
    /// one name can't be read under another.
    /// </summary>
    public string ApplicationName { get; set; } = "";

    /// <summary>The app's PostgreSQL connection string. The keys go in their own schema there.</summary>
    public string ConnectionString { get; set; } = "";

    /// <summary>The schema holding the keys table, created if missing. Default: <c>data_protection</c>.</summary>
    public string Schema { get; set; } = "data_protection";

    /// <summary>
    /// The secret that encrypts the keys in the database: at least 32 characters, for example from
    /// <c>openssl rand -base64 32</c>. Without it, the stored keys, and so everything they protect, can't be read.
    /// </summary>
    public string MasterKey { get; set; } = "";

    /// <summary>
    /// Earlier master keys, still needed to read keys stored before <see cref="MasterKey"/> was changed. New keys are
    /// always encrypted with <see cref="MasterKey"/>.
    /// </summary>
    public List<string> PreviousMasterKeys { get; set; } = [];

    /// <summary>
    /// Optional: a folder of key files written by <c>PersistKeysToFileSystem</c>. Keys there that aren't in the
    /// database yet are copied in when the app first uses Data Protection, so data protected with them stays readable.
    /// </summary>
    public string? ImportKeysFrom { get; set; }

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(ApplicationName))
        {
            throw new InvalidOperationException("BlueRaiz.DataProtection: set ApplicationName, the same one the app has always used.");
        }

        if (string.IsNullOrWhiteSpace(ConnectionString))
        {
            throw new InvalidOperationException("BlueRaiz.DataProtection: set ConnectionString, the app's PostgreSQL database.");
        }

        if (!SchemaName().IsMatch(Schema))
        {
            throw new InvalidOperationException($"BlueRaiz.DataProtection: {Schema} isn't a valid schema name. Use lowercase letters, digits and underscores.");
        }

        foreach (var key in PreviousMasterKeys.Prepend(MasterKey))
        {
            if ((key ?? "").Trim().Length < MasterKeyRing.MinimumLength)
            {
                throw new InvalidOperationException(
                    $"BlueRaiz.DataProtection: a master key must be at least {MasterKeyRing.MinimumLength} characters. Generate one with: openssl rand -base64 32");
            }
        }
    }

    [GeneratedRegex("^[a-z_][a-z0-9_]{0,62}$")]
    private static partial Regex SchemaName();
}
