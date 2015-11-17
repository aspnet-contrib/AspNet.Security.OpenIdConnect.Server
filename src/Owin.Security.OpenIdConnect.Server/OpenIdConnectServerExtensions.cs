/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
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
        /// <param name="configuration">
        /// A delegate allowing to modify the options
        /// controlling the behavior of the OpenID Connect server.
        /// </param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOpenIdConnectServer(
            this IAppBuilder app, Action<OpenIdConnectServerOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OpenIdConnectServerOptions();
            configuration(options);

            return app.UseOpenIdConnectServer(options);
        }

        /// <summary>
        /// Adds a new OpenID Connect server instance in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="options">The options controlling the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOpenIdConnectServer(this IAppBuilder app, OpenIdConnectServerOptions options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            // If no key has been explicitly added, use the fallback mode.
            if (options.EncryptingCredentials.Count == 0 ||
                options.SigningCredentials.Count == 0) {
                // Resolve a logger instance from the services provider.
                var logger = app.CreateLogger<OpenIdConnectServerMiddleware>();

                var directory = OpenIdConnectServerHelpers.GetDefaultKeyStorageDirectory();

                // Ensure the directory exists.
                if (!directory.Exists) {
                    directory.Create();
                    directory.Refresh();
                }

                // Get a data protector from the services provider.
                var protector = app.CreateDataProtector(
                    typeof(OpenIdConnectServerMiddleware).Namespace,
                    options.AuthenticationType, "Keys", "v1");

                foreach (var file in directory.EnumerateFiles("*.key")) {
                    using (var buffer = new MemoryStream())
                    using (var stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read)) {
                        // Copy the key content to the buffer.
                        stream.CopyTo(buffer);

                        // Extract the key material using the data protector.
                        // Ignore the key if the decryption process failed.
                        string usage;
                        var parameters = OpenIdConnectServerHelpers.DecryptKey(protector, buffer.ToArray(), out usage);
                        if (parameters == null) {
                            logger.WriteVerbose($"An invalid/incompatible key was ignored: {file.FullName}.");

                            continue;
                        }

                        var provider = new RSACryptoServiceProvider();
                        provider.ImportParameters(parameters.Value);

                        if (string.Equals(usage, "Encryption", StringComparison.OrdinalIgnoreCase)) {
                            // Only add the encryption key if none has been explictly added.
                            if (options.EncryptingCredentials.Count != 0) {
                                continue;
                            }

                            logger.WriteInformation("An existing key was automatically added to the " +
                                                   $"encryption credentials list: {file.FullName}.");

                            // Add the key to the encryption credentials list.
                            options.EncryptingCredentials.AddKey(new RsaSecurityKey(provider));
                        }

                        else if (string.Equals(usage, "Signing", StringComparison.OrdinalIgnoreCase)) {
                            // Only add the signing key if none has been explictly added.
                            if (options.SigningCredentials.Count != 0) {
                                continue;
                            }

                            logger.WriteInformation("An existing key was automatically added to the " +
                                                   $"signing credentials list: {file.FullName}.");

                            // Add the key to the signing credentials list.
                            options.SigningCredentials.AddKey(new RsaSecurityKey(provider));
                        }
                    }
                }

                // If no encryption key has been found, generate and persist a new RSA key.
                if (options.EncryptingCredentials.Count == 0) {
                    // Generate a new 2048 bit RSA key and export its public/private parameters.
                    var provider = new RSACryptoServiceProvider(2048);
                    var parameters = provider.ExportParameters(/* includePrivateParameters */ true);

                    // Generate a new file name for the key and determine its absolute path.
                    var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

                    using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                        // Encrypt the key using the data protector.
                        var bytes = OpenIdConnectServerHelpers.EncryptKey(protector, parameters, usage: "Encryption");

                        // Write the encrypted key to the file stream.
                        stream.Write(bytes, 0, bytes.Length);
                    }

                    logger.WriteInformation("A new RSA key was automatically generated, added to the " +
                                           $"encryption credentials list and persisted on the disk: {path}.");

                    options.EncryptingCredentials.AddKey(new RsaSecurityKey(provider));
                }

                // If no signing key has been found, generate and persist a new RSA key.
                if (options.SigningCredentials.Count == 0) {
                    // Generate a new 2048 bit RSA key and export its public/private parameters.
                    var provider = new RSACryptoServiceProvider(2048);
                    var parameters = provider.ExportParameters(/* includePrivateParameters */ true);

                    // Generate a new file name for the key and determine its absolute path.
                    var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

                    using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                        // Encrypt the key using the data protector.
                        var bytes = OpenIdConnectServerHelpers.EncryptKey(protector, parameters, usage: "Signing");

                        // Write the encrypted key to the file stream.
                        stream.Write(bytes, 0, bytes.Length);
                    }

                    logger.WriteInformation("A new RSA key was automatically generated, added to the " +
                                           $"signing credentials list and persisted on the disk: {path}.");

                    options.SigningCredentials.AddKey(new RsaSecurityKey(provider));
                }
            }

            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> to decrypt
        /// authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to decrypt authorization requests received by the server.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            this IList<EncryptingCredentials> credentials, X509Certificate2 certificate) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (certificate.PrivateKey == null) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            credentials.Add(new X509EncryptingCredentials(certificate));

            return credentials;
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from an embedded resource
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            this IList<EncryptingCredentials> credentials,
            Assembly assembly, string resource, string password) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (assembly == null) {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource)) {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }

            using (var stream = assembly.GetManifestResourceStream(resource)) {
                if (stream == null) {
                    throw new InvalidOperationException("The certificate was not found in the given assembly.");
                }

                return credentials.AddCertificate(stream, password);
            }
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> contained in a stream
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            this IList<EncryptingCredentials> credentials, Stream stream, string password) {
            return credentials.AddCertificate(stream, password, X509KeyStorageFlags.Exportable |
                                                                X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> contained in a stream
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            this IList<EncryptingCredentials> credentials, Stream stream,
            string password, X509KeyStorageFlags flags) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (stream == null) {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }

            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);

                return credentials.AddCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
            }
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the X509 machine store
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            this IList<EncryptingCredentials> credentials, string thumbprint) {
            return credentials.AddCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the given X509 store
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="name">The name of the X509 store.</param>
        /// <param name="location">The location of the X509 store.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            this IList<EncryptingCredentials> credentials,
            string thumbprint, StoreName name, StoreLocation location) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            var certificate = OpenIdConnectServerHelpers.GetCertificate(name, location, thumbprint);
            if (certificate == null) {
                throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
            }

            return credentials.AddCertificate(certificate);
        }

        /// <summary>
        /// Adds a specific <see cref="SecurityKey"/> to decrypt
        /// authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddKey(this IList<EncryptingCredentials> credentials, SecurityKey key) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (key == null) {
                throw new ArgumentNullException(nameof(key));
            }

            var asymmetricSecurityKey = key as AsymmetricSecurityKey;
            if (asymmetricSecurityKey != null) {
                var x509SecurityKey = asymmetricSecurityKey as X509SecurityKey;
                if (x509SecurityKey != null) {
                    return credentials.AddCertificate(x509SecurityKey.Certificate);
                }

                var x509AsymmetricSecurityKey = asymmetricSecurityKey as X509AsymmetricSecurityKey;
                if (x509AsymmetricSecurityKey != null) {
                    // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                    // Reflection is the only way to get the certificate used to create the security key.
                    var field = typeof(X509AsymmetricSecurityKey).GetField(
                        name: "certificate",
                        bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);

                    return credentials.AddCertificate((X509Certificate2) field.GetValue(x509AsymmetricSecurityKey));
                }

                var rsaSecurityKey = asymmetricSecurityKey as RsaSecurityKey;
                if (rsaSecurityKey != null) {
                    // When using a RSA key, the public part is used to uniquely identify the key.
                    var algorithm = (RSA) rsaSecurityKey.GetAsymmetricAlgorithm(SecurityAlgorithms.RsaOaepKeyWrap, false);
                    var identifier = new SecurityKeyIdentifier(new RsaKeyIdentifierClause(algorithm));

                    credentials.Add(new EncryptingCredentials(key, identifier, SecurityAlgorithms.RsaOaepKeyWrap));

                    return credentials;
                }
            }

            var symmetricSecurityKey = key as SymmetricSecurityKey;
            if (symmetricSecurityKey != null) {
                // When using an in-memory symmetric key, no identifier clause can be inferred from the key itself.
                // To prevent the built-in security token handlers from throwing an exception, a default identifier is added.
                var identifier = new SecurityKeyIdentifier(new LocalIdKeyIdentifierClause("Default"));

                credentials.Add(new EncryptingCredentials(key, identifier, SecurityAlgorithms.Aes256Encryption));

                return credentials;
            }

            throw new InvalidOperationException("The encryption key type is not supported.");
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            this IList<SigningCredentials> credentials, X509Certificate2 certificate) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (certificate.PrivateKey == null) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            credentials.Add(new X509SigningCredentials(certificate));

            return credentials;
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            this IList<SigningCredentials> credentials,
            Assembly assembly, string resource, string password) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (assembly == null) {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource)) {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }

            using (var stream = assembly.GetManifestResourceStream(resource)) {
                if (stream == null) {
                    throw new InvalidOperationException("The certificate was not found in the given assembly.");
                }

                return credentials.AddCertificate(stream, password);
            }
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            this IList<SigningCredentials> credentials, Stream stream, string password) {
            return credentials.AddCertificate(stream, password, X509KeyStorageFlags.Exportable |
                                                                X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            this IList<SigningCredentials> credentials, Stream stream,
            string password, X509KeyStorageFlags flags) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (stream == null) {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }
            
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);

                return credentials.AddCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
            }
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the
        /// X509 machine store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            this IList<SigningCredentials> credentials, string thumbprint) {
            return credentials.AddCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the
        /// given X509 store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="name">The name of the X509 store.</param>
        /// <param name="location">The location of the X509 store.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            this IList<SigningCredentials> credentials,
            string thumbprint, StoreName name, StoreLocation location) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            var certificate = OpenIdConnectServerHelpers.GetCertificate(name, location, thumbprint);
            if (certificate == null) {
                throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
            }

            return credentials.AddCertificate(certificate);
        }

        /// <summary>
        /// Adds a specific <see cref="SecurityKey"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddKey(this IList<SigningCredentials> credentials, SecurityKey key) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (key == null) {
                throw new ArgumentNullException(nameof(key));
            }

            credentials.Add(new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest));

            return credentials;
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
                throw new ArgumentNullException(nameof(options));
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
                throw new ArgumentNullException(nameof(context));
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
                throw new ArgumentNullException(nameof(context));
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
                throw new ArgumentNullException(nameof(context));
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
                throw new ArgumentNullException(nameof(context));
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
                throw new ArgumentNullException(nameof(app));
            }

            return new OpenIdConnectServerHelpers.EnhancedTicketDataFormat(app.CreateDataProtector(purposes));
        }
    }
}
