/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features;
using Microsoft.Framework.Caching.Distributed;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.OptionsModel;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// ASP.NET-powered OpenID Connect server and to retrieve various
    /// OpenID Connect-related contexts from the ASP.NET environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Configures the settings used by the OpenID Connect server.
        /// </summary>
        /// <param name="services">The services collection.</param>
        /// <param name="options">Options which control the behavior of the OpenID Connect server.</param>
        /// <returns>The services collection.</returns>
        public static IServiceCollection ConfigureOpenIdConnectServer(
            [NotNull] this IServiceCollection services,
            [NotNull] Action<OpenIdConnectServerOptions> options) {
            return services.Configure(options);
        }

        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer([NotNull] this IApplicationBuilder app) {
            return app.UseOpenIdConnectServer(options => { });
        }

        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="options">Options which control the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIdConnectServerOptions> options) {
            return app.UseMiddleware<OpenIdConnectServerMiddleware>(new ConfigureOptions<OpenIdConnectServerOptions>(options));
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(
            [NotNull] this OpenIdConnectServerOptions options,
            [NotNull] X509Certificate2 certificate) {
            if (!certificate.HasPrivateKey) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            return options.UseKey(new X509SecurityKey(certificate));
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(
            [NotNull] this OpenIdConnectServerOptions options, [NotNull] Assembly assembly,
            [NotNull] string resource, [NotNull] string password) {
            using (var stream = assembly.GetManifestResourceStream(resource)) {
                if (stream == null) {
                    throw new InvalidOperationException("The certificate was not found in the given assembly.");
                }

                return options.UseCertificate(stream, password);
            }
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(
            [NotNull] this OpenIdConnectServerOptions options,
            [NotNull] Stream stream, [NotNull] string password) {
            return options.UseCertificate(stream, password, X509KeyStorageFlags.Exportable |
                                                            X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(
            [NotNull] this OpenIdConnectServerOptions options,
            [NotNull] Stream stream, [NotNull] string password, X509KeyStorageFlags flags) {
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);

                return options.UseCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
            }
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// X509 machine store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(
            [NotNull] this OpenIdConnectServerOptions options,
            [NotNull] string thumbprint, [NotNull] string password) {
            return options.UseCertificate(thumbprint, password, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// given X509 store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="name">The name of the X509 store.</param>
        /// <param name="location">The location of the X509 store.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate([NotNull] this OpenIdConnectServerOptions options,
            [NotNull] string thumbprint, [NotNull] string password, StoreName name, StoreLocation location) {
            var store = new X509Store(name, location);

            try {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                var certificate = certificates.OfType<X509Certificate2>().SingleOrDefault();
                if (certificate == null) {
                    throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
                }

                return options.UseCertificate(certificate);
            }

            finally {
#if DNXCORE50
                store.Dispose();
#else
                store.Close();
#endif
            }
        }

        /// <summary>
        /// Uses a specific <see cref="SecurityKey"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseKey(
            [NotNull] this OpenIdConnectServerOptions options, [NotNull] SecurityKey key) {
            options.SigningCredentials = new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest);

            return options;
        }

        /// <summary>
        /// Configures the OpenID Connect server to issue opaque access tokens produced by the data protection block.
        /// Opaque tokens cannot be read by client applications or resource servers if they don't share identical keys.
        /// Note: you can use the validation endpoint to validate opaque tokens directly on the authorization server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseOpaqueTokens([NotNull] this OpenIdConnectServerOptions options) {
            options.AccessTokenHandler = null;

            return options;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest([NotNull] this HttpContext context) {
            return GetFeature(context).Request;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> request in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectRequest([NotNull] this HttpContext context, OpenIdConnectMessage request) {
            GetFeature(context).Request = request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current response from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current response.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectResponse([NotNull] this HttpContext context) {
            return GetFeature(context).Response;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> response in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectResponse([NotNull] this HttpContext context, OpenIdConnectMessage response) {
            GetFeature(context).Response = response;
        }

        /// <summary>
        /// Creates a new enhanced ticket format that supports serializing
        /// <see cref="ClaimsIdentity.Actor"/> and <see cref="Claim.Properties"/>.
        /// </summary>
        /// <param name="provider">The data protector provider</param>
        /// <param name="purposes">The unique values used to initialize the data protector.</param>
        public static ISecureDataFormat<AuthenticationTicket> CreateTicketFormat(
            [NotNull] this IDataProtectionProvider provider, [NotNull] params string[] purposes) {
            return new EnhancedTicketDataFormat(provider.CreateProtector(purposes));
        }
 
        internal static string GetIssuer([NotNull] this HttpContext context, [NotNull] OpenIdConnectServerOptions options) {
            var issuer = options.Issuer;
            if (issuer == null) {
                if (!Uri.TryCreate(context.Request.Scheme + "://" + context.Request.Host +
                                   context.Request.PathBase, UriKind.Absolute, out issuer)) {
                    throw new InvalidOperationException("The issuer address cannot be inferred from the current request");
                }
            }

            return issuer.AbsoluteUri;
        }

        internal static string AddPath([NotNull] this string address, PathString path) {
            if (address.EndsWith("/")) {
                address = address.Substring(0, address.Length - 1);
            }

            return address + path;
        }

        internal static IEnumerable<KeyValuePair<string, string[]>> ToDictionary(this IReadableStringCollection collection) {
            return collection.Select(item => new KeyValuePair<string, string[]>(item.Key, item.Value.ToArray()));
        }

        private static IOpenIdConnectServerFeature GetFeature(HttpContext context) {
            var feature = context.Features.Get<IOpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            return feature;
        }

        internal static Task SetAsync(
            [NotNull] this IDistributedCache cache, [NotNull] string key,
            [NotNull] Func<DistributedCacheEntryOptions, byte[]> factory) {
            var options = new DistributedCacheEntryOptions();
            var buffer = factory(options);

            return cache.SetAsync(key, buffer, options);
        }

        internal static bool IsSupportedAlgorithm([NotNull] this SecurityKey securityKey, [NotNull] string algorithm) {
            // Note: SecurityKey currently doesn't support IsSupportedAlgorithm.
            // To work around this limitation, this static extensions tries to
            // determine whether the security key supports RSA w/ SHA2 or not.
            if (!string.Equals(algorithm, SecurityAlgorithms.RsaSha256Signature, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(algorithm, SecurityAlgorithms.RsaSha384Signature, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(algorithm, SecurityAlgorithms.RsaSha512Signature, StringComparison.OrdinalIgnoreCase)) {
                return false;
            }

            var rsaSecurityKey = securityKey as RsaSecurityKey;
            if (rsaSecurityKey != null) {
                return rsaSecurityKey.HasPublicKey &&
                       rsaSecurityKey.HasPrivateKey;
            }

            var x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey == null || !x509SecurityKey.HasPublicKey) {
                return false;
            }

            var rsaPrivateKey = x509SecurityKey.PrivateKey as RSA;
            if (rsaPrivateKey == null) {
                return false;
            }

            return true;
        }

        internal static AuthenticationProperties Copy([NotNull] this AuthenticationProperties properties) {
            return new AuthenticationProperties(properties.Items.ToDictionary(pair => pair.Key, pair => pair.Value));
        }

        internal static AuthenticationTicket Copy([NotNull] this AuthenticationTicket ticket) {
            return new AuthenticationTicket(ticket.Principal, ticket.Properties.Copy(), ticket.AuthenticationScheme);
        }

        internal static void CopyTo(this AuthenticationProperties source, AuthenticationProperties destination) {
            if (source == null || destination == null) {
                return;
            }

            if (ReferenceEquals(destination, source)) {
                return;
            }

            foreach (var property in source.Items) {
                destination.Items[property.Key] = property.Value;
            }
        }

        internal static string GetProperty(this AuthenticationProperties properties, string property) {
            if (properties == null) {
                return null;
            }

            string value;
            if (!properties.Items.TryGetValue(property, out value)) {
                return null;
            }

            return value;
        }

        internal static IEnumerable<string> GetAudiences(this AuthenticationProperties properties) {
            return properties?.GetProperty(OpenIdConnectConstants.Extra.Audience)?.Split(' ') ?? Enumerable.Empty<string>();
        }

        internal static IEnumerable<string> GetResources(this AuthenticationProperties properties) {
            return properties?.GetProperty(OpenIdConnectConstants.Extra.Resource)?.Split(' ') ?? Enumerable.Empty<string>();
        }

        internal static IEnumerable<string> GetScopes(this AuthenticationProperties properties) {
            return properties?.GetProperty(OpenIdConnectConstants.Extra.Scope)?.Split(' ') ?? Enumerable.Empty<string>();
        }

        internal static void SetAudiences(this AuthenticationProperties properties, IEnumerable<string> audiences) {
            properties.Items[OpenIdConnectConstants.Extra.Audience] = string.Join(" ", audiences);
        }

        internal static bool ContainsScope(this AuthenticationTicket ticket, string scope) {
            return ticket.Properties.GetScopes().Contains(scope);
        }

        internal static bool ContainsSet(this IEnumerable<string> source, IEnumerable<string> set) {
            if (source == null || set == null) {
                return false;
            }

            return new HashSet<string>(source).IsSupersetOf(set);
        }

        // Remove when the built-in ticket serializer supports Claim.Properties.
        // See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/71
        private sealed class EnhancedTicketDataFormat : SecureDataFormat<AuthenticationTicket> {
            private static readonly EnhancedTicketSerializer Serializer = new EnhancedTicketSerializer();

            public EnhancedTicketDataFormat(IDataProtector protector)
                : base(Serializer, protector, TextEncodings.Base64Url) {
            }

            private sealed class EnhancedTicketSerializer : IDataSerializer<AuthenticationTicket> {
                private const int FormatVersion = 3;

                public byte[] Serialize(AuthenticationTicket model) {
                    using (var memory = new MemoryStream())
                    using (var writer = new BinaryWriter(memory)) {
                        writer.Write(FormatVersion);

                        writer.Write(model.AuthenticationScheme);
                        writer.Write(model.Principal.Identities.Count());

                        foreach (var identity in model.Principal.Identities) {
                            WriteIdentity(writer, identity);
                        }

                        PropertiesSerializer.Write(writer, model.Properties);

                        return memory.ToArray();
                    }
                }

                public AuthenticationTicket Deserialize(byte[] data) {
                    using (var memory = new MemoryStream(data))
                    using (var reader = new BinaryReader(memory)) {
                        if (reader.ReadInt32() != FormatVersion) {
                            return null;
                        }

                        var scheme = reader.ReadString();

                        var identities = new ClaimsIdentity[reader.ReadInt32()];
                        for (int index = 0; index != identities.Length; ++index) {
                            identities[index] = ReadIdentity(reader);
                        }
                    
                        var properties = PropertiesSerializer.Read(reader);

                        return new AuthenticationTicket(new ClaimsPrincipal(identities), properties, scheme);
                    }
                }

                private static void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity) {
                    var authenticationType = identity.AuthenticationType ?? string.Empty;

                    writer.Write(authenticationType);
                    WriteWithDefault(writer, identity.NameClaimType, DefaultValues.NameClaimType);
                    WriteWithDefault(writer, identity.RoleClaimType, DefaultValues.RoleClaimType);
                    writer.Write(identity.Claims.Count());

                    foreach (var claim in identity.Claims) {
                        WriteWithDefault(writer, claim.Type, identity.NameClaimType);
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
                    int count = reader.ReadInt32();
                    var claims = new Claim[count];

                    for (int index = 0; index != count; ++index) {
                        string type = ReadWithDefault(reader, nameClaimType);
                        string value = reader.ReadString();
                        string valueType = ReadWithDefault(reader, DefaultValues.StringValueType);
                        string issuer = ReadWithDefault(reader, DefaultValues.LocalAuthority);
                        string originalIssuer = ReadWithDefault(reader, issuer);

                        claims[index] = new Claim(type, value, valueType, issuer, originalIssuer);

                        var x = reader.ReadInt32();

                        for (int j = 0; j != x; ++j) {
                            claims[index].Properties.Add(key: reader.ReadString(), value: reader.ReadString());
                        }
                    }

                    var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);

                    if (reader.ReadBoolean()) {
                        identity.Actor = ReadIdentity(reader);
                    }

                    return identity;
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
