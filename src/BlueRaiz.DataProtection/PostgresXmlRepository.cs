using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace BlueRaiz.DataProtection;

// Stores each key (and key revocation) as one row, its XML encrypted with the master key. The table is created on
// first use; key files from ImportKeysFrom are copied in at the same time.
internal sealed class PostgresXmlRepository : IXmlRepository
{
    private readonly BlueRaizDataProtectionOptions options;
    private readonly MasterKeyRing masterKeys;
    private readonly ILogger logger;
    private readonly string table;
    private readonly object gate = new();
    private bool ready;

    public PostgresXmlRepository(BlueRaizDataProtectionOptions options, ILogger logger)
    {
        this.options = options;
        this.logger = logger;
        masterKeys = new MasterKeyRing(options.MasterKey, options.PreviousMasterKeys);
        table = $"\"{options.Schema}\".\"keys\"";
    }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        EnsureReady();
        using var connection = Open();
        using var command = new NpgsqlCommand($"select friendly_name, master_key_id, payload from {table} order by id", connection);
        using var reader = command.ExecuteReader();
        List<XElement> elements = [];
        while (reader.Read())
        {
            var name = reader.GetString(0);
            var keyId = reader.GetString(1);
            if (!masterKeys.Knows(keyId))
            {
                throw new InvalidOperationException(
                    $"BlueRaiz.DataProtection: {name} in {table} was encrypted with a master key that isn't configured. "
                    + "Set the master key it was stored with, or add it to PreviousMasterKeys. Without it, the data it protects can't be read.");
            }

            var xml = masterKeys.Decrypt(keyId, (byte[])reader.GetValue(2), name)
                ?? throw new InvalidOperationException($"BlueRaiz.DataProtection: {name} in {table} couldn't be decrypted. It was changed outside this library.");
            elements.Add(XElement.Parse(Encoding.UTF8.GetString(xml)));
        }

        return elements;
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        EnsureReady();
        using var connection = Open();
        Insert(connection, element, friendlyName);
    }

    private void Insert(NpgsqlConnection connection, XElement element, string friendlyName)
    {
        var xml = Encoding.UTF8.GetBytes(element.ToString(SaveOptions.DisableFormatting));
        using var command = new NpgsqlCommand(
            $"insert into {table} (friendly_name, master_key_id, payload) values (@name, @key, @payload) on conflict (friendly_name) do nothing",
            connection);
        command.Parameters.AddWithValue("name", friendlyName);
        command.Parameters.AddWithValue("key", masterKeys.CurrentId);
        command.Parameters.AddWithValue("payload", masterKeys.Encrypt(xml, friendlyName));
        command.ExecuteNonQuery();
    }

    private void EnsureReady()
    {
        lock (gate)
        {
            if (ready) return;
            using var connection = Open();
            using (var create = new NpgsqlCommand(
                       $"""
                        create schema if not exists "{options.Schema}";
                        create table if not exists {table} (
                            id bigint generated always as identity primary key,
                            friendly_name text not null unique,
                            master_key_id text not null,
                            payload bytea not null,
                            created_at timestamptz not null default now()
                        );
                        """, connection))
            {
                create.ExecuteNonQuery();
            }

            Import(connection);
            ready = true;
        }
    }

    // Key files as PersistKeysToFileSystem writes them: one XML file per key or revocation, named after it.
    private void Import(NpgsqlConnection connection)
    {
        if (string.IsNullOrWhiteSpace(options.ImportKeysFrom) || !Directory.Exists(options.ImportKeysFrom)) return;

        var imported = 0;
        foreach (var file in Directory.EnumerateFiles(options.ImportKeysFrom, "*.xml"))
        {
            var name = Path.GetFileNameWithoutExtension(file);
            using (var exists = new NpgsqlCommand($"select 1 from {table} where friendly_name = @name", connection))
            {
                exists.Parameters.AddWithValue("name", name);
                if (exists.ExecuteScalar() is not null) continue;
            }

            XElement element;
            try
            {
                element = XElement.Load(file);
            }
            catch (Exception exception) when (exception is System.Xml.XmlException or IOException or UnauthorizedAccessException)
            {
                logger.LogWarning(exception, "BlueRaiz.DataProtection: skipped {File}, which isn't a readable key file.", file);
                continue;
            }

            Insert(connection, element, name);
            imported++;
        }

        if (imported > 0)
        {
            logger.LogInformation("BlueRaiz.DataProtection: copied {Count} key file(s) from {Folder} into the database.", imported, options.ImportKeysFrom);
        }
    }

    private NpgsqlConnection Open()
    {
        var connection = new NpgsqlConnection(options.ConnectionString);
        connection.Open();
        return connection;
    }
}
