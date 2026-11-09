using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace BlueRaiz.DataProtection.Tests;

// Needs PostgreSQL: TEST_DATABASE is its connection string. Each test uses its own schema.
public sealed class DataProtectionTests : IDisposable
{
    private const string App = "Tests.App";
    private const string Purpose = "credentials";
    private static readonly string Database = Environment.GetEnvironmentVariable("TEST_DATABASE")
        ?? "Host=localhost;Username=postgres;Password=postgres";

    private readonly string schema = "t_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string masterKey = Convert.ToBase64String(Guid.NewGuid().ToByteArray()) + Convert.ToBase64String(Guid.NewGuid().ToByteArray());
    private readonly List<ServiceProvider> providers = [];
    private readonly List<string> folders = [];

    private IDataProtector Protector(string? master = null, IEnumerable<string>? previous = null, string? import = null)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddBlueRaizDataProtection(o =>
        {
            o.ApplicationName = App;
            o.ConnectionString = Database;
            o.Schema = schema;
            o.MasterKey = master ?? masterKey;
            o.PreviousMasterKeys = previous?.ToList() ?? [];
            o.ImportKeysFrom = import;
        });
        var provider = services.BuildServiceProvider();
        providers.Add(provider);
        return provider.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose);
    }

    private async Task<List<(string Name, byte[] Payload)>> RowsAsync()
    {
        await using var connection = new NpgsqlConnection(Database);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"select friendly_name, payload from \"{schema}\".\"keys\"", connection);
        await using var reader = await command.ExecuteReaderAsync();
        List<(string, byte[])> rows = [];
        while (await reader.ReadAsync()) rows.Add((reader.GetString(0), (byte[])reader.GetValue(1)));
        return rows;
    }

    [Fact]
    public async Task Another_instance_with_the_same_database_and_master_key_reads_the_data()
    {
        var secret = Protector().Protect("the payment api key");

        Assert.Equal("the payment api key", Protector().Unprotect(secret));

        // The key's XML, with its secret, isn't stored readable.
        var row = Assert.Single(await RowsAsync());
        Assert.StartsWith("key-", row.Name);
        Assert.DoesNotContain("masterKey", Encoding.UTF8.GetString(row.Payload));
    }

    [Fact]
    public void A_different_master_key_fails_loudly_instead_of_starting_over()
    {
        var secret = Protector().Protect("the payment api key");

        var error = Assert.ThrowsAny<Exception>(() => Protector(master: new string('x', 40)).Unprotect(secret));
        Assert.Contains("master key that isn't configured", Messages(error));
    }

    [Fact]
    public void A_changed_master_key_still_reads_keys_stored_with_the_previous_one()
    {
        var secret = Protector().Protect("the payment api key");
        var rotated = new string('r', 40);

        var protector = Protector(master: rotated, previous: [masterKey]);
        Assert.Equal("the payment api key", protector.Unprotect(secret));
        Assert.Equal("new", protector.Unprotect(protector.Protect("new")));
    }

    [Fact]
    public void Key_files_are_imported_once_and_then_not_needed()
    {
        var folder = Directory.CreateTempSubdirectory("brdp-").FullName;
        folders.Add(folder);
        var files = new ServiceCollection().AddLogging();
        files.AddDataProtection().SetApplicationName(App).PersistKeysToFileSystem(new DirectoryInfo(folder));
        using var fileProvider = files.BuildServiceProvider();
        var secret = fileProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose).Protect("saved before the move");

        Assert.Equal("saved before the move", Protector(import: folder).Unprotect(secret));

        Directory.Delete(folder, recursive: true);
        Assert.Equal("saved before the move", Protector().Unprotect(secret));
    }

    [Theory]
    [InlineData("too-short")]
    [InlineData("")]
    public void A_weak_master_key_is_refused(string master)
    {
        var error = Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBlueRaizDataProtection(o =>
        {
            o.ApplicationName = App;
            o.ConnectionString = Database;
            o.MasterKey = master;
        }));
        Assert.Contains("at least 32 characters", error.Message);
    }

    [Fact]
    public void Settings_come_from_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DataProtection:MasterKey"] = masterKey,
            ["DataProtection:Schema"] = schema,
            ["DataProtection:PreviousMasterKeys"] = new string('a', 40) + ", " + new string('b', 40),
        }).Build();
        var services = new ServiceCollection().AddLogging();
        services.AddBlueRaizDataProtection(configuration, App, Database);
        using var provider = services.BuildServiceProvider();

        var secret = provider.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose).Protect("from config");
        Assert.Equal("from config", Protector().Unprotect(secret));
    }

    private static string Messages(Exception error)
    {
        var text = new StringBuilder();
        for (Exception? e = error; e is not null; e = e.InnerException) text.AppendLine(e.Message);
        return text.ToString();
    }

    public void Dispose()
    {
        foreach (var provider in providers) provider.Dispose();
        foreach (var folder in folders.Where(Directory.Exists)) Directory.Delete(folder, recursive: true);
        using var connection = new NpgsqlConnection(Database);
        connection.Open();
        using var drop = new NpgsqlCommand($"drop schema if exists \"{schema}\" cascade", connection);
        drop.ExecuteNonQuery();
    }
}
