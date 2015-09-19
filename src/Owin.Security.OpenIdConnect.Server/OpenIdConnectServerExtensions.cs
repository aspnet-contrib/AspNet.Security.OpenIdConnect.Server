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
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;
using Owin.Security.OpenIdConnect.Extensions;
using Owin.Security.OpenIdConnect.Server;

namespace Owin {
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// OWIN-powered OpenID Connect server and to retrieve various
    /// OpenID Connect-related contexts from the OWIN environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Adds a new OpenID Connect server instance in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="options">The settings controlling the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOpenIdConnectServer(this IAppBuilder app, OpenIdConnectServerOptions options) {
            if (app == null) {
                throw new ArgumentNullException("app");
            }

            if (options == null) {
                throw new ArgumentNullException("options");
            }

            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }

        /// <summary>
        /// Adds a new OpenID Connect server instance in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="configuration">A delegate allowing to change the OpenID Connect server's settings.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOpenIdConnectServer(this IAppBuilder app, Action<OpenIdConnectServerOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException("app");
            }

            if (configuration == null) {
                throw new ArgumentNullException("configuration");
            }

            var options = new OpenIdConnectServerOptions();
            configuration(options);

            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(this OpenIdConnectServerOptions options, X509Certificate2 certificate) {
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            if (certificate == null) {
                throw new ArgumentNullException("certificate");
            }

            if (certificate.PrivateKey == null) {
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
            this OpenIdConnectServerOptions options,
            Assembly assembly, string resource, string password) {
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            if (assembly == null) {
                throw new ArgumentNullException("assembly");
            }

            if (string.IsNullOrEmpty(resource)) {
                throw new ArgumentNullException("resource");
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException("password");
            }

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
        public static OpenIdConnectServerOptions UseCertificate(this OpenIdConnectServerOptions options, Stream stream, string password) {
            return options.UseCertificate(stream, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
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
            this OpenIdConnectServerOptions options, Stream stream,
            string password, X509KeyStorageFlags flags) {
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            if (stream == null) {
                throw new ArgumentNullException("stream");
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException("password");
            }
            
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
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(this OpenIdConnectServerOptions options, string thumbprint) {
            return options.UseCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// given X509 store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="name">The name of the X509 store.</param>
        /// <param name="location">The location of the X509 store.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseCertificate(this OpenIdConnectServerOptions options,
            string thumbprint, StoreName name, StoreLocation location) {
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentNullException("thumbprint");
            }

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
                store.Close();
            }
        }

        /// <summary>
        /// Uses a specific <see cref="SecurityKey"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseKey(this OpenIdConnectServerOptions options, SecurityKey key) {
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            if (key == null) {
                throw new ArgumentNullException("key");
            }

            options.SigningCredentials.Add(new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest));

            return options;
        }

        /// <summary>
        /// Uses the <see cref="RsaSecurityKey"/> stored in the given file.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="file">The file containing the encrypted key.</param>
        /// <param name="protector">The data protector used to decrypt the key.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseKey(this OpenIdConnectServerOptions options, FileInfo file, IDataProtector protector) {
            using (var buffer = new MemoryStream())
            using (var stream = file.Open(FileMode.Open)) {
                // Copy the key content to the buffer.
                stream.CopyTo(buffer);

                // Extract the key material using the data protector.
                var parameters = protector.DecryptKey(buffer.ToArray());
                if (parameters == null) {
                    throw new InvalidOperationException("Invalid or corrupted key");
                }

                var provider = new RSACryptoServiceProvider();
                provider.ImportParameters(parameters.Value);

                options.UseKey(new RsaSecurityKey(provider));
            }

            return options;
        }

        /// <summary>
        /// Uses the <see cref="RsaSecurityKey"/> stored in the given directory.
        /// Note: this extension will automatically ignore incompatible keys.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="directory">The directory containing the encrypted keys.</param>
        /// <param name="protector">The data protector used to decrypt the key.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseKeys(
            this OpenIdConnectServerOptions options,
            DirectoryInfo directory, IDataProtector protector) {
            if (!directory.Exists) {
                throw new InvalidOperationException("The directory does not exist");
            }

            foreach (var file in directory.EnumerateFiles("*.key")) {
                using (var buffer = new MemoryStream())
                using (var stream = file.Open(FileMode.Open)) {
                    // Copy the key content to the buffer.
                    stream.CopyTo(buffer);

                    // Extract the key material using the data protector.
                    // Ignore the key if the decryption process failed.
                    var parameters = protector.DecryptKey(buffer.ToArray());
                    if (parameters == null) {
                        continue;
                    }

                    var provider = new RSACryptoServiceProvider();
                    provider.ImportParameters(parameters.Value);

                    options.UseKey(new RsaSecurityKey(provider));
                }
            }

            return options;
        }

        /// <summary>
        /// Configures the OpenID Connect server to issue opaque access tokens produced by the data protection block.
        /// Opaque tokens cannot be read by client applications or resource servers if they don't share identical keys.
        /// Note: you can use the validation endpoint to validate opaque tokens directly on the authorization server.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseOpaqueTokens(this OpenIdConnectServerOptions options) {
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            options.AccessTokenHandler = null;

            return options;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest(this IOwinContext context) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            return context.Get<OpenIdConnectMessage>(OpenIdConnectConstants.Environment.Request);
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> request in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectRequest(this IOwinContext context, OpenIdConnectMessage request) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            context.Set(OpenIdConnectConstants.Environment.Request, request);
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current response from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current response.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectResponse(this IOwinContext context) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            return context.Get<OpenIdConnectMessage>(OpenIdConnectConstants.Environment.Response);
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> response in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectResponse(this IOwinContext context, OpenIdConnectMessage response) {
            if (context == null) {
                throw new ArgumentNullException("context");
            }

            context.Set(OpenIdConnectConstants.Environment.Response, response);
        }

        /// <summary>
        /// Creates a new enhanced ticket format that supports serializing
        /// <see cref="ClaimsIdentity.Actor"/> and <see cref="Claim.Properties"/>.
        /// </summary>
        /// <param name="app">The web application builder</param>
        /// <param name="purposes">The unique values used to initialize the data protector.</param>
        public static ISecureDataFormat<AuthenticationTicket> CreateTicketFormat(this IAppBuilder app, params string[] purposes) {
            if (app == null) {
                throw new ArgumentNullException("app");
            }

            return new EnhancedTicketDataFormat(app.CreateDataProtector(purposes));
        }

        /// <summary>
        /// Encrypts a RSA security key using the given data protector.
        /// </summary>
        /// <param name="protector">The data protector used to encrypt the key.</param>
        /// <param name="parameters">The key material.</param>
        /// <returns>The array of <see cref="byte"/> containing the protected key.</returns>
        public static byte[] EncryptKey(this IDataProtector protector, RSAParameters parameters) {
            if (protector == null) {
                throw new ArgumentNullException("protector");
            }

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(/* version: */ 1);
                writer.Write(/* algorithm: */ "RSA");

                // Serialize the RSA parameters to the key file.
                writer.Write(parameters.D.Length);
                writer.Write(parameters.D);
                writer.Write(parameters.DP.Length);
                writer.Write(parameters.DP);
                writer.Write(parameters.DQ.Length);
                writer.Write(parameters.DQ);
                writer.Write(parameters.Exponent.Length);
                writer.Write(parameters.Exponent);
                writer.Write(parameters.InverseQ.Length);
                writer.Write(parameters.InverseQ);
                writer.Write(parameters.Modulus.Length);
                writer.Write(parameters.Modulus);
                writer.Write(parameters.P.Length);
                writer.Write(parameters.P);
                writer.Write(parameters.Q.Length);
                writer.Write(parameters.Q);

                // Encrypt the key using the data protection block.
                return protector.Protect(stream.ToArray());
            }
        }

        /// <summary>
        /// Decrypts a RSA key using the given data protector.
        /// </summary>
        /// <param name="protector">The data protector used to decrypt the key.</param>
        /// <param name="buffer">The array of <see cref="byte"/> containing the protected key.</param>
        /// <returns>The key material or <c>null</c> if the decryption process failed.</returns>
        public static RSAParameters? DecryptKey(this IDataProtector protector, byte[] buffer) {
            if (protector == null) {
                throw new ArgumentNullException("protector");
            }

            if (buffer == null) {
                throw new ArgumentNullException("buffer");
            }

            // Note: an exception thrown in this block may be caused by a corrupted or inappropriate key
            // (for instance, if the key was created for another application or another environment).
            // Always catch the exception and return null in this case to avoid leaking sensitive data.
            try {
                var bytes = protector.Unprotect(buffer);
                if (bytes == null) {
                    return null;
                }

                using (var stream = new MemoryStream(bytes))
                using (var reader = new BinaryReader(stream)) {
                    if (/* version: */ reader.ReadInt32() != 1) {
                        return null;
                    }

                    // Note: only RSA keys are currently supported. Return null if another format has been used.
                    if (!string.Equals(/* algorithm: */ reader.ReadString(), "RSA", StringComparison.OrdinalIgnoreCase)) {
                        return null;
                    }

                    // Extract the RSA parameters from the serialized key.
                    return new RSAParameters {
                        D = reader.ReadBytes(reader.ReadInt32()),
                        DP = reader.ReadBytes(reader.ReadInt32()),
                        DQ = reader.ReadBytes(reader.ReadInt32()),
                        Exponent = reader.ReadBytes(reader.ReadInt32()),
                        InverseQ = reader.ReadBytes(reader.ReadInt32()),
                        Modulus = reader.ReadBytes(reader.ReadInt32()),
                        P = reader.ReadBytes(reader.ReadInt32()),
                        Q = reader.ReadBytes(reader.ReadInt32())
                    };
                }
            }

            catch {
                return null;
            }
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

        internal static AuthenticationProperties Copy(this AuthenticationProperties properties) {
            if (properties == null) {
                return null;
            }

            return new AuthenticationProperties(properties.Dictionary.ToDictionary(pair => pair.Key, pair => pair.Value));
        }

        internal static AuthenticationTicket Copy(this AuthenticationTicket ticket) {
            return new AuthenticationTicket(ticket.Identity, ticket.Properties.Copy());
        }

        internal static void CopyTo(this AuthenticationProperties source, AuthenticationProperties destination) {
            if (source == null || destination == null) {
                return;
            }

            if (ReferenceEquals(destination, source)) {
                return;
            }

            foreach (var property in source.Dictionary) {
                destination.Dictionary[property.Key] = property.Value;
            }
        }

        internal static string GetProperty(this AuthenticationProperties properties, string property) {
            if (properties == null) {
                return null;
            }

            string value;
            if (!properties.Dictionary.TryGetValue(property, out value)) {
                return null;
            }

            return value;
        }

        internal static IEnumerable<string> GetAudiences(this AuthenticationProperties properties) {
            if (properties == null) {
                return null;
            }

            var audience = properties.GetProperty(OpenIdConnectConstants.Extra.Audience);
            if (string.IsNullOrEmpty(audience)) {
                return Enumerable.Empty<string>();
            }

            return audience.Split(' ');
        }

        internal static IEnumerable<string> GetResources(this AuthenticationProperties properties) {
            if (properties == null) {
                return null;
            }

            var resource = properties.GetProperty(OpenIdConnectConstants.Extra.Resource);
            if (string.IsNullOrEmpty(resource)) {
                return Enumerable.Empty<string>();
            }

            return resource.Split(' ');
        }

        internal static IEnumerable<string> GetScopes(this AuthenticationProperties properties) {
            if (properties == null) {
                return null;
            }

            var scope = properties.GetProperty(OpenIdConnectConstants.Extra.Scope);
            if (string.IsNullOrEmpty(scope)) {
                return Enumerable.Empty<string>();
            }

            return scope.Split(' ');
        }

        internal static void SetAudiences(this AuthenticationProperties properties, IEnumerable<string> audiences) {
            properties.Dictionary[OpenIdConnectConstants.Extra.Audience] = string.Join(" ", audiences);
        }

        internal static bool ContainsProperty(this AuthenticationTicket ticket, string property) {
            if (ticket == null) {
                return false;
            }

            return ticket.Properties.Dictionary.ContainsKey(property);
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
