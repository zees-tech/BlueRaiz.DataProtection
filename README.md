# BlueRaiz.DataProtection

ASP.NET Core Data Protection keeps its keys in files by default. Lose those files (a rebuilt server, a deleted
volume, a new container) and everything the app encrypted with them, such as saved API keys and passwords, can never
be read again.

This package keeps the keys **in the app's own PostgreSQL database**, encrypted with a **master key** you provide:

- The keys are backed up, restored and moved together with the data they protect.
- A copy of the database alone isn't enough to read them: that also needs the master key.
- Any number of app instances share the keys, wherever they run.

Works with .NET 8 and later.

## Use

```sh
dotnet add package BlueRaiz.DataProtection
```

```csharp
builder.Services.AddBlueRaizDataProtection(
    builder.Configuration,
    applicationName: "MyApp",   // keep it the same forever: data protected under one name can't be read under another
    connectionString: builder.Configuration.GetConnectionString("Default")!);
```

Settings, from the `DataProtection` section (environment variables: `DataProtection__MasterKey` and so on):

| Setting | |
|---|---|
| `MasterKey` | **Required.** At least 32 characters. Generate one with `openssl rand -base64 32`. |
| `PreviousMasterKeys` | Earlier master keys, comma-separated, still needed after changing `MasterKey`. |
| `ImportKeysFrom` | A folder of key files from `PersistKeysToFileSystem`, copied into the database on first use. |
| `Schema` | Where the `keys` table goes. Default `data_protection`; created if missing. |

Or configure it in code: `services.AddBlueRaizDataProtection(o => { o.ApplicationName = ...; o.ConnectionString = ...; o.MasterKey = ...; })`.

## The master key

- Keep it as a secret in your deployment platform **and** in a password manager. To restore the app anywhere you
  need the database backup plus this key; without the key, the encrypted data is lost.
- If the configured master key doesn't match the stored keys, the app fails with a clear error instead of quietly
  making new keys, so nothing is overwritten.
- **Changing it:** set the new one as `MasterKey` and move the old one to `PreviousMasterKeys`. New keys use the new
  master key; keys stored earlier still need the old one, so keep it there.

## Moving from key files

Set `ImportKeysFrom` to the folder the app used with `PersistKeysToFileSystem` (for example `/keys`) and keep the
same application name. On first use, the keys there are copied into the database; data protected with them stays
readable. After that, the folder isn't needed.

## How it's stored

One row per key or revocation in `<schema>.keys`: its name, the id of the master key that encrypted it, and its XML
encrypted with AES-256-GCM, bound to the row's name. The master key is derived with HKDF-SHA256 from the secret you
provide.

## Develop

Tests need PostgreSQL; set `TEST_DATABASE` to its connection string:

```sh
TEST_DATABASE="Host=localhost;Username=postgres;Password=postgres" dotnet test
```

Releases: push a tag `vX.Y.Z` matching `<Version>` in the project file. The workflow tests, packs and publishes it to
nuget.org through Trusted Publishing (a policy on nuget.org for this repository and `ci.yml`; no API key is stored).
