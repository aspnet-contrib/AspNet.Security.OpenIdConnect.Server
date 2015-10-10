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
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// ASP.NET-powered OpenID Connect server and to retrieve various
    /// OpenID Connect-related contexts from the ASP.NET environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions {
        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="configuration">A delegate allowing to modify the options controlling the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIdConnectServerConfiguration> configuration) {
            var options = new OpenIdConnectServerConfiguration(app);

            // By default, enable AllowInsecureHttp in development/testing environments.
            var environment = app.ApplicationServices.GetRequiredService<IHostingEnvironment>();
            options.Options.AllowInsecureHttp = environment.IsDevelopment() || environment.IsEnvironment("Testing");

            configuration(options);

            // If no key has been explicitly added, use the fallback mode.
            if (options.Options.SigningCredentials.Count == 0) {
                var directory = GetDefaultKeyStorageDirectory();

                // Ensure the directory exists.
                if (!directory.Exists) {
                    directory.Create();
                    directory.Refresh();
                }

                options.UseKeys(directory);
            }

            return app.UseMiddleware<OpenIdConnectServerMiddleware>(options.Options);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseCertificate(
            [NotNull] this OpenIdConnectServerConfiguration configuration,
            [NotNull] X509Certificate2 certificate) {
            if (!certificate.HasPrivateKey) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            return configuration.UseKey(new X509SecurityKey(certificate));
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseCertificate(
            [NotNull] this OpenIdConnectServerConfiguration configuration,
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password) {
            using (var stream = assembly.GetManifestResourceStream(resource)) {
                if (stream == null) {
                    throw new InvalidOperationException("The certificate was not found in the given assembly.");
                }

                return configuration.UseCertificate(stream, password);
            }
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseCertificate(
            [NotNull] this OpenIdConnectServerConfiguration configuration,
            [NotNull] Stream stream, [NotNull] string password) {
            return configuration.UseCertificate(stream, password, X509KeyStorageFlags.Exportable |
                                                                  X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseCertificate(
            [NotNull] this OpenIdConnectServerConfiguration configuration,
            [NotNull] Stream stream, [NotNull] string password, X509KeyStorageFlags flags) {
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);

                return configuration.UseCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
            }
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// X509 machine store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseCertificate(
            [NotNull] this OpenIdConnectServerConfiguration configuration, [NotNull] string thumbprint) {
            return configuration.UseCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// given X509 store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="name">The name of the X509 store.</param>
        /// <param name="location">The location of the X509 store.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseCertificate(
            [NotNull] this OpenIdConnectServerConfiguration configuration,
            [NotNull] string thumbprint, StoreName name, StoreLocation location) {
            var store = new X509Store(name, location);

            try {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                var certificate = certificates.OfType<X509Certificate2>().SingleOrDefault();
                if (certificate == null) {
                    throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
                }

                return configuration.UseCertificate(certificate);
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
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseKey(
            [NotNull] this OpenIdConnectServerConfiguration configuration, [NotNull] SecurityKey key) {
            configuration.Options.SigningCredentials.Add(new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest));

            return configuration;
        }

        /// <summary>
        /// Uses the <see cref="RsaSecurityKey"/>s stored in the given directory.
        /// Note: this extension will automatically ignore incompatible keys and
        /// create a new RSA key if none has been previously added.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="directory">The directory containing the encrypted keys.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseKeys(
            [NotNull] this OpenIdConnectServerConfiguration configuration, [NotNull] DirectoryInfo directory) {
            // Gets a data protector from the services provider.
            var protector = configuration.Builder.ApplicationServices.GetDataProtector(
                typeof(OpenIdConnectServerMiddleware).Namespace,
                configuration.Options.AuthenticationScheme, "Signing_Credentials", "v1");

            return configuration.UseKeys(directory, protector);
        }

        /// <summary>
        /// Uses the <see cref="RsaSecurityKey"/>s stored in the given directory.
        /// Note: this extension will automatically ignore incompatible keys and
        /// create a new RSA key if none has been previously added.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <param name="directory">The directory containing the encrypted keys.</param>
        /// <param name="protector">The data protector used to decrypt the key.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseKeys(
            [NotNull] this OpenIdConnectServerConfiguration configuration,
            [NotNull] DirectoryInfo directory, [NotNull] IDataProtector protector) {
            if (!directory.Exists) {
                throw new InvalidOperationException("The directory does not exist");
            }

            foreach (var file in directory.EnumerateFiles("*.key")) {
                using (var buffer = new MemoryStream())
                using (var stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    // Copy the key content to the buffer.
                    stream.CopyTo(buffer);

                    // Extract the key material using the data protector.
                    // Ignore the key if the decryption process failed.
                    var parameters = protector.DecryptKey(buffer.ToArray());
                    if (parameters == null) {
                        continue;
                    }

                    configuration.UseKey(new RsaSecurityKey(parameters.Value));
                }
            }

            // If no signing key has been found, generate and persist a new RSA key.
            if (configuration.Options.SigningCredentials.Count == 0) {
                // Generate a new 2048 bit RSA key and export its public/private parameters.
                var provider = new RSACryptoServiceProvider(2048);
                var parameters = provider.ExportParameters(includePrivateParameters: true);

                // Generate a new file name for the key and determine its absolute path.
                var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

                using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                    // Encrypt the key using the data protector.
                    var bytes = protector.EncryptKey(parameters);

                    // Write the encrypted key to the file stream.
                    stream.Write(bytes, 0, bytes.Length);
                }

                configuration.UseKey(new RsaSecurityKey(parameters));
            }

            return configuration;
        }

        /// <summary>
        /// Configures the OpenID Connect server to issue opaque access tokens produced by the data protection block.
        /// Opaque tokens cannot be read by client applications or resource servers if they don't share identical keys.
        /// Note: you can use the validation endpoint to validate opaque tokens directly on the authorization server.
        /// </summary>
        /// <param name="configuration">The options used to configure the OpenID Connect server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerConfiguration UseOpaqueTokens([NotNull] this OpenIdConnectServerConfiguration configuration) {
            configuration.Options.AccessTokenHandler = null;

            return configuration;
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
        /// Encrypts a RSA security key using the given data protector.
        /// </summary>
        /// <param name="protector">The data protector used to encrypt the key.</param>
        /// <param name="parameters">The key material.</param>
        /// <returns>The array of <see cref="byte"/> containing the protected key.</returns>
        public static byte[] EncryptKey([NotNull] this IDataProtector protector, [NotNull] RSAParameters parameters) {
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
        public static RSAParameters? DecryptKey([NotNull] this IDataProtector protector, [NotNull] byte[] buffer) {
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

        private static DirectoryInfo GetDefaultKeyStorageDirectory() {
            string path;

            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"))) {
                path = Environment.GetEnvironmentVariable("HOME");
                if (!string.IsNullOrEmpty(path)) {
                    return GetKeyStorageDirectoryFromBaseAppDataPath(path);
                }
            }

#if !DNXCORE50
            // Note: Environment.GetFolderPath may return null if the user profile is not loaded.
            path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            if (!string.IsNullOrEmpty(path)) {
                return GetKeyStorageDirectoryFromBaseAppDataPath(path);
            }

            // Returning the current directory is safe as keys are always encrypted using the
            // data protection system, making the keys unreadable outside this environment.
            return new DirectoryInfo(Directory.GetCurrentDirectory());
#else

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
                return new DirectoryInfo(Path.Combine(path, ".aspnet", "aspnet-contrib", "aspnet-oidc-server"));
            }
            
            // Returning the current directory is safe as keys are always encrypted using the
            // data protection system, making the keys unreadable outside this environment.
            return new DirectoryInfo(Directory.GetCurrentDirectory());
#endif
        }

        private static DirectoryInfo GetKeyStorageDirectoryFromBaseAppDataPath(string path) {
            return new DirectoryInfo(Path.Combine(path, "ASP.NET", "aspnet-contrib", "aspnet-oidc-server"));
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

        internal static string GetNonce(this AuthenticationProperties properties) {
            return properties?.GetProperty(OpenIdConnectConstants.Extra.Nonce);
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

        internal static bool ContainsProperty(this AuthenticationTicket ticket, string property) {
            if (ticket == null) {
                return false;
            }

            return ticket.Properties.Items.ContainsKey(property);
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
    }
}
