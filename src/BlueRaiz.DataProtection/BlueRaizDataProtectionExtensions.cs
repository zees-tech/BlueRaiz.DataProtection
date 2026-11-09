using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BlueRaiz.DataProtection;

/// <summary>Registers Data Protection with its keys in the app's PostgreSQL database.</summary>
public static class BlueRaizDataProtectionExtensions
{
    /// <summary>
    /// Keeps the app's Data Protection keys in its PostgreSQL database, encrypted with a master key.
    /// </summary>
    public static IDataProtectionBuilder AddBlueRaizDataProtection(this IServiceCollection services, Action<BlueRaizDataProtectionOptions> configure)
    {
        var options = new BlueRaizDataProtectionOptions();
        configure(options);
        options.Validate();

        // After AddDataProtection's own setup, as the framework's PersistKeysTo* methods do.
        var builder = services.AddDataProtection().SetApplicationName(options.ApplicationName);
        services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(provider => new ConfigureOptions<KeyManagementOptions>(keys =>
        {
            keys.XmlRepository = new PostgresXmlRepository(options, provider.GetRequiredService<ILoggerFactory>().CreateLogger("BlueRaiz.DataProtection"));
            // The repository encrypts every row with the master key, so the framework's own per-key encryption is
            // left out (and with it, its warning that no key encryptor is configured).
            keys.XmlEncryptor = new NullXmlEncryptor(provider);
        }));

        return builder;
    }

    /// <summary>
    /// The same, with the settings read from a configuration section (by default <c>DataProtection</c>):
    /// <c>MasterKey</c>, <c>PreviousMasterKeys</c> (a list, or comma-separated), <c>ImportKeysFrom</c> and <c>Schema</c>.
    /// </summary>
    public static IDataProtectionBuilder AddBlueRaizDataProtection(
        this IServiceCollection services, IConfiguration configuration, string applicationName, string connectionString, string section = "DataProtection")
    {
        var settings = configuration.GetSection(section);
        return services.AddBlueRaizDataProtection(options =>
        {
            options.ApplicationName = applicationName;
            options.ConnectionString = connectionString;
            options.MasterKey = settings["MasterKey"] ?? "";
            options.ImportKeysFrom = settings["ImportKeysFrom"];
            if (settings["Schema"] is { Length: > 0 } schema) options.Schema = schema;

            var previous = settings.GetSection("PreviousMasterKeys");
            options.PreviousMasterKeys = previous.GetChildren().Select(c => c.Value)
                .Concat((previous.Value ?? "").Split(','))
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v!.Trim())
                .ToList();
        });
    }
}
