using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;

namespace Owin.Security.OpenIdConnect.Server {
    public static class OpenIdConnectServerHelpers {
        internal static DirectoryInfo GetDefaultKeyStorageDirectory() {
            string path;

            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"))) {
                path = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrEmpty(path)) {
                    return GetKeyStorageDirectoryFromBaseAppDataPath(path);
                }
            }

            // Note: Environment.GetFolderPath may return null if the user profile is not loaded.
            path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(path);
            }

            // Try to resolve the AppData/Local folder
            // using the LOCALAPPDATA environment variable.
            path = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(path);
            }

            // If the LOCALAPPDATA environment variable was not found,
            // try to determine the actual AppData/Local path from USERPROFILE.
            path = Environment.GetEnvironmentVariable("USERPROFILE");
            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(Path.Combine(path, "AppData", "Local"));
            }

            // On Linux environments, use the HOME variable.
            path = Environment.GetEnvironmentVariable("HOME");
            if (!string.IsNullOrEmpty(path)) {
                return new DirectoryInfo(Path.Combine(path, ".aspnet", "aspnet-contrib", "owin-oidc-server"));
            }

            // Returning the current directory is safe as keys are always encrypted using the
            // data protection system, making the keys unreadable outside this environment.
            return new DirectoryInfo(Directory.GetCurrentDirectory());
        }

        private static DirectoryInfo GetKeyStorageDirectoryFromBaseAppDataPath(string path) {
            return new DirectoryInfo(Path.Combine(path, "ASP.NET", "aspnet-contrib", "owin-oidc-server"));
        }

        internal static string GetIssuer(this IOwinContext context, OpenIdConnectServerOptions options) {
            var issuer = options.Issuer;
            if (issuer == null) {
                if (!Uri.TryCreate(context.Request.Scheme + "://" + context.Request.Host +
                                   context.Request.PathBase, UriKind.Absolute, out issuer)) {
                    throw new InvalidOperationException("The issuer address cannot be inferred from the current request");
                }
            }

            return issuer.AbsoluteUri;
        }

        internal static string AddPath(this string address, PathString path) {
            if (address.EndsWith("/")) {
                address = address.Substring(0, address.Length - 1);
            }

            return address + path;
        }

        internal static bool ContainsSet(this IEnumerable<string> source, IEnumerable<string> set) {
            if (source == null || set == null) {
                return false;
            }

            return new HashSet<string>(source).IsSupersetOf(set);
        }

        internal sealed class EnhancedTicketDataFormat : SecureDataFormat<AuthenticationTicket> {
            private static readonly EnhancedTicketSerializer Serializer = new EnhancedTicketSerializer();

            public EnhancedTicketDataFormat(IDataProtector protector)
                : base(Serializer, protector, TextEncodings.Base64Url) {
            }

            private sealed class EnhancedTicketSerializer : IDataSerializer<AuthenticationTicket> {
                private const int FormatVersion = 3;

                public byte[] Serialize(AuthenticationTicket model) {
                    if (model == null) {
                        throw new ArgumentNullException("model");
                    }

                    using (var buffer = new MemoryStream())
                    using (var writer = new BinaryWriter(buffer)) {
                        writer.Write(FormatVersion);

                        WriteIdentity(writer, model.Identity);
                        PropertiesSerializer.Write(writer, model.Properties);

                        return buffer.ToArray();
                    }
                }

                public AuthenticationTicket Deserialize(byte[] data) {
                    if (data == null) {
                        throw new ArgumentNullException("data");
                    }

                    using (var buffer = new MemoryStream(data))
                    using (var reader = new BinaryReader(buffer)) {
                        if (reader.ReadInt32() != FormatVersion) {
                            return null;
                        }

                        var identity = ReadIdentity(reader);
                        var properties = PropertiesSerializer.Read(reader);

                        return new AuthenticationTicket(identity, properties);
                    }
                }

                private static void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity) {
                    writer.Write(identity.AuthenticationType);
                    WriteWithDefault(writer, identity.NameClaimType, DefaultValues.NameClaimType);
                    WriteWithDefault(writer, identity.RoleClaimType, DefaultValues.RoleClaimType);
                    writer.Write(identity.Claims.Count());

                    foreach (var claim in identity.Claims) {
                        WriteClaim(writer, claim, identity.NameClaimType);
                    }

                    var context = identity.BootstrapContext as BootstrapContext;
                    if (context == null || string.IsNullOrEmpty(context.Token)) {
                        writer.Write(0);
                    }

                    else {
                        writer.Write(context.Token.Length);
                        writer.Write(context.Token);
                    }

                    if (identity.Actor != null) {
                        writer.Write(true);
                        WriteIdentity(writer, identity.Actor);
                    }

                    else {
                        writer.Write(false);
                    }
                }

                private static ClaimsIdentity ReadIdentity(BinaryReader reader) {
                    var authenticationType = reader.ReadString();
                    var nameClaimType = ReadWithDefault(reader, DefaultValues.NameClaimType);
                    var roleClaimType = ReadWithDefault(reader, DefaultValues.RoleClaimType);
                    var count = reader.ReadInt32();

                    var claims = new Claim[count];

                    for (int index = 0; index != count; ++index) {
                        claims[index] = ReadClaim(reader, nameClaimType);
                    }

                    var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);

                    int bootstrapContextSize = reader.ReadInt32();
                    if (bootstrapContextSize > 0) {
                        identity.BootstrapContext = new BootstrapContext(reader.ReadString());
                    }

                    if (reader.ReadBoolean()) {
                        identity.Actor = ReadIdentity(reader);
                    }

                    return identity;
                }

                private static void WriteClaim(BinaryWriter writer, Claim claim, string nameClaimType) {
                    WriteWithDefault(writer, claim.Type, nameClaimType);
                    writer.Write(claim.Value);
                    WriteWithDefault(writer, claim.ValueType, DefaultValues.StringValueType);
                    WriteWithDefault(writer, claim.Issuer, DefaultValues.LocalAuthority);
                    WriteWithDefault(writer, claim.OriginalIssuer, claim.Issuer);
                    writer.Write(claim.Properties.Count);

                    foreach (var property in claim.Properties) {
                        writer.Write(property.Key);
                        writer.Write(property.Value);
                    }
                }

                private static Claim ReadClaim(BinaryReader reader, string nameClaimType) {
                    var type = ReadWithDefault(reader, nameClaimType);
                    var value = reader.ReadString();
                    var valueType = ReadWithDefault(reader, DefaultValues.StringValueType);
                    var issuer = ReadWithDefault(reader, DefaultValues.LocalAuthority);
                    var originalIssuer = ReadWithDefault(reader, issuer);
                    var count = reader.ReadInt32();

                    var claim = new Claim(type, value, valueType, issuer, originalIssuer);

                    for (var index = 0; index != count; ++index) {
                        claim.Properties.Add(key: reader.ReadString(), value: reader.ReadString());
                    }

                    return claim;
                }

                private static void WriteWithDefault(BinaryWriter writer, string value, string defaultValue) {
                    if (string.Equals(value, defaultValue, StringComparison.Ordinal)) {
                        writer.Write(DefaultValues.DefaultStringPlaceholder);
                    }

                    else {
                        writer.Write(value);
                    }
                }

                private static string ReadWithDefault(BinaryReader reader, string defaultValue) {
                    string value = reader.ReadString();
                    if (string.Equals(value, DefaultValues.DefaultStringPlaceholder, StringComparison.Ordinal)) {
                        return defaultValue;
                    }

                    return value;
                }

                private static class DefaultValues {
                    public const string DefaultStringPlaceholder = "\0";
                    public const string NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                    public const string RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
                    public const string LocalAuthority = "LOCAL AUTHORITY";
                    public const string StringValueType = "http://www.w3.org/2001/XMLSchema#string";
                }
            }
        }
    }
}
