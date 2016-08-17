/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.Security;
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
            [NotNull] this IAppBuilder app,
            [NotNull] Action<OpenIdConnectServerOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OpenIdConnectServerOptions();
            configuration(options);

            return app.Use(typeof(OpenIdConnectServerMiddleware), app, options);
        }

        /// <summary>
        /// Adds a new OpenID Connect server instance in the OWIN pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="options">The options controlling the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOpenIdConnectServer(
            [NotNull] this IAppBuilder app,
            [NotNull] OpenIdConnectServerOptions options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
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
            [NotNull] this IList<EncryptingCredentials> credentials,
            [NotNull] X509Certificate2 certificate) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (certificate.PrivateKey == null) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            var identifier = new SecurityKeyIdentifier {
                new X509IssuerSerialKeyIdentifierClause(certificate),
                new X509RawDataKeyIdentifierClause(certificate),
                new X509ThumbprintKeyIdentifierClause(certificate),
                new LocalIdKeyIdentifierClause(certificate.Thumbprint.ToUpperInvariant())
            };

            // Mark the security key identifier as read-only to
            // ensure it can't be altered during a request.
            identifier.MakeReadOnly();

            credentials.Add(new X509EncryptingCredentials(certificate, identifier));

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
            [NotNull] this IList<EncryptingCredentials> credentials,
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password) {
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
            [NotNull] this IList<EncryptingCredentials> credentials, [NotNull] Stream stream, [NotNull] string password) {
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
            [NotNull] this IList<EncryptingCredentials> credentials, [NotNull] Stream stream,
            [NotNull] string password, X509KeyStorageFlags flags) {
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
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the X.509 machine store
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            [NotNull] this IList<EncryptingCredentials> credentials, [NotNull] string thumbprint) {
            return credentials.AddCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the given X.509 store
        /// to decrypt authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddCertificate(
            [NotNull] this IList<EncryptingCredentials> credentials,
            [NotNull] string thumbprint, StoreName name, StoreLocation location) {
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
        /// Adds a new ephemeral key used to decrypt the authorization requests received by the OpenID Connect server:
        /// the key is discarded when the application shuts down and authorization requests encrypted using this key
        /// cannot be decrypted when the key is lost. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The signing credentials.</returns>
        public static IList<EncryptingCredentials> AddEphemeralKey([NotNull] this IList<EncryptingCredentials> credentials) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var algorithm = RSA.Create();

            if (algorithm.KeySize < 2048) {
                algorithm.KeySize = 2048;
            }

            // Note: RSACng cannot be used as it's not available on Mono.
            if (algorithm.KeySize < 2048 && algorithm is RSACryptoServiceProvider) {
                algorithm.Dispose();
                algorithm = new RSACryptoServiceProvider(2048);
            }

            if (algorithm.KeySize < 2048) {
                throw new InvalidOperationException("The ephemeral key generation failed.");
            }

            return credentials.AddKey(new RsaSecurityKey(algorithm));
        }

        /// <summary>
        /// Adds a specific <see cref="SecurityKey"/> to decrypt
        /// authorization requests received by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddKey(
            [NotNull] this IList<EncryptingCredentials> credentials, [NotNull] SecurityKey key) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (key == null) {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaOaepKeyWrap)) {
                var x509SecurityKey = key as X509SecurityKey;
                if (x509SecurityKey != null) {
                    return credentials.AddCertificate(x509SecurityKey.Certificate);
                }

                var x509AsymmetricSecurityKey = key as X509AsymmetricSecurityKey;
                if (x509AsymmetricSecurityKey != null) {
                    // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                    // Reflection is the only way to get the certificate used to create the security key.
                    var field = typeof(X509AsymmetricSecurityKey).GetField(
                        name: "certificate",
                        bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);
                    Debug.Assert(field != null);

                    return credentials.AddCertificate((X509Certificate2) field.GetValue(x509AsymmetricSecurityKey));
                }

                // Create an empty security key identifier.
                var identifier = new SecurityKeyIdentifier();

                var rsaSecurityKey = key as RsaSecurityKey;
                if (rsaSecurityKey != null) {
                    // When using a RSA key, the public part is used to uniquely identify the key.
                    var algorithm = (RSA) rsaSecurityKey.GetAsymmetricAlgorithm(
                        algorithm: SecurityAlgorithms.RsaOaepKeyWrap,
                        requiresPrivateKey: false);

                    Debug.Assert(algorithm != null,
                        "SecurityKey.GetAsymmetricAlgorithm() shouldn't return a null algorithm.");

                    // Export the RSA public key to extract a key identifier based on the modulus component.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Modulus != null,
                        "RSA.ExportParameters() shouldn't return a null modulus.");

                    // Only use the 40 first chars of the base64url-encoded modulus.
                    var kid = Base64UrlEncoder.Encode(parameters.Modulus);
                    kid = kid.Substring(0, Math.Min(kid.Length, 40)).ToUpperInvariant();

                    identifier.Add(new RsaKeyIdentifierClause(algorithm));
                    identifier.Add(new LocalIdKeyIdentifierClause(kid));
                }

                // Mark the security key identifier as read-only to
                // ensure it can't be altered during a request.
                identifier.MakeReadOnly();

                credentials.Add(new EncryptingCredentials(key, identifier, SecurityAlgorithms.RsaOaepKeyWrap));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256Encryption)) {
                // When using an in-memory symmetric key, no identifier clause can be inferred from the key itself.
                // To prevent the built-in security token handlers from throwing an exception, a default identifier is added.
                var identifier = new SecurityKeyIdentifier(new LocalIdKeyIdentifierClause("Default"));

                // Mark the security key identifier as read-only to
                // ensure it can't be altered during a request.
                identifier.MakeReadOnly();

                credentials.Add(new EncryptingCredentials(key, identifier, SecurityAlgorithms.Aes256Encryption));

                return credentials;
            }

            throw new InvalidOperationException("A key wrap algorithm cannot be automatically inferred from the encryption key. " +
                                                "Consider using 'options.EncryptingCredentials.Add(EncryptingCredentials)' instead.");
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials,
            [NotNull] X509Certificate2 certificate) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (certificate.PrivateKey == null) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            var identifier = new SecurityKeyIdentifier {
                new X509IssuerSerialKeyIdentifierClause(certificate),
                new X509RawDataKeyIdentifierClause(certificate),
                new X509ThumbprintKeyIdentifierClause(certificate),
                new LocalIdKeyIdentifierClause(certificate.Thumbprint.ToUpperInvariant())
            };

            // Mark the security key identifier as read-only to
            // ensure it can't be altered during a request.
            identifier.MakeReadOnly();

            credentials.Add(new X509SigningCredentials(certificate, identifier));

            return credentials;
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials,
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password) {
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
        /// a stream to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] Stream stream, [NotNull] string password) {
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
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] Stream stream,
            [NotNull] string password, X509KeyStorageFlags flags) {
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
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the X.509
        /// machine store to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] string thumbprint) {
            return credentials.AddCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the given
        /// X.509 store to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials,
            [NotNull] string thumbprint, StoreName name, StoreLocation location) {
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
        /// Adds a new ephemeral key used to sign the tokens issued by the OpenID Connect server:
        /// the key is discarded when the application shuts down and tokens signed using this key
        /// are automatically invalidated. This method should only be used during development:
        /// on production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddEphemeralKey([NotNull] this IList<SigningCredentials> credentials) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var algorithm = RSA.Create();

            if (algorithm.KeySize < 2048) {
                algorithm.KeySize = 2048;
            }

            // Note: RSACng cannot be used as it's not available on Mono.
            if (algorithm.KeySize < 2048 && algorithm is RSACryptoServiceProvider) {
                algorithm.Dispose();
                algorithm = new RSACryptoServiceProvider(2048);
            }

            if (algorithm.KeySize < 2048) {
                throw new InvalidOperationException("The ephemeral key generation failed.");
            }

            return credentials.AddKey(new RsaSecurityKey(algorithm));
        }

        /// <summary>
        /// Adds a specific <see cref="SecurityKey"/> to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddKey(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] SecurityKey key) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (key == null) {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                var x509SecurityKey = key as X509SecurityKey;
                if (x509SecurityKey != null) {
                    return credentials.AddCertificate(x509SecurityKey.Certificate);
                }

                var x509AsymmetricSecurityKey = key as X509AsymmetricSecurityKey;
                if (x509AsymmetricSecurityKey != null) {
                    // The X.509 certificate is not directly accessible when using X509AsymmetricSecurityKey.
                    // Reflection is the only way to get the certificate used to create the security key.
                    var field = typeof(X509AsymmetricSecurityKey).GetField(
                        name: "certificate",
                        bindingAttr: BindingFlags.Instance | BindingFlags.NonPublic);
                    Debug.Assert(field != null);

                    return credentials.AddCertificate((X509Certificate2) field.GetValue(x509AsymmetricSecurityKey));
                }

                // Create an empty security key identifier.
                var identifier = new SecurityKeyIdentifier();

                var rsaSecurityKey = key as RsaSecurityKey;
                if (rsaSecurityKey != null) {
                    // Resolve the underlying algorithm from the security key.
                    var algorithm = (RSA) rsaSecurityKey.GetAsymmetricAlgorithm(
                        algorithm: SecurityAlgorithms.RsaSha256Signature,
                        requiresPrivateKey: false);

                    Debug.Assert(algorithm != null,
                        "SecurityKey.GetAsymmetricAlgorithm() shouldn't return a null algorithm.");

                    // Export the RSA public key to extract a key identifier based on the modulus component.
                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

                    Debug.Assert(parameters.Modulus != null,
                        "RSA.ExportParameters() shouldn't return a null modulus.");

                    // Only use the 40 first chars of the base64url-encoded modulus.
                    var kid = Base64UrlEncoder.Encode(parameters.Modulus);
                    kid = kid.Substring(0, Math.Min(kid.Length, 40)).ToUpperInvariant();

                    identifier.Add(new RsaKeyIdentifierClause(algorithm));
                    identifier.Add(new LocalIdKeyIdentifierClause(kid));
                }

                // Mark the security key identifier as read-only to
                // ensure it can't be altered during a request.
                identifier.MakeReadOnly();

                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature,
                                                            SecurityAlgorithms.Sha256Digest, identifier));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256Signature)) {
                // When using an in-memory symmetric key, no identifier clause can be inferred from the key itself.
                // To prevent the built-in security token handlers from throwing an exception, a default identifier is added.
                var identifier = new SecurityKeyIdentifier(new LocalIdKeyIdentifierClause("Default"));

                // Mark the security key identifier as read-only to
                // ensure it can't be altered during a request.
                identifier.MakeReadOnly();

                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature,
                                                            SecurityAlgorithms.Sha256Digest, identifier));

                return credentials;
            }

            throw new InvalidOperationException("A signature algorithm cannot be automatically inferred from the signing key. " +
                                                "Consider using 'options.SigningCredentials.Add(SigningCredentials)' instead.");
        }

        /// <summary>
        /// Configures the OpenID Connect server to enable logging.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <param name="configuration">The delegate used to configure the logger factory.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseLogging(
            [NotNull] this OpenIdConnectServerOptions options,
            [NotNull] Action<ILoggerFactory> configuration) {
            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var factory = new LoggerFactory();
            configuration(factory);

            options.Logger = factory.CreateLogger<OpenIdConnectServerMiddleware>();

            return options;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectRequest"/> instance
        /// associated with the current request from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectRequest"/> associated with the current request.</returns>
        public static OpenIdConnectRequest GetOpenIdConnectRequest([NotNull] this IOwinContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Get<OpenIdConnectRequest>(OpenIdConnectConstants.Environment.Request);
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectResponse"/> instance
        /// associated with the current response from the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <returns>The <see cref="OpenIdConnectResponse"/> associated with the current response.</returns>
        public static OpenIdConnectResponse GetOpenIdConnectResponse([NotNull] this IOwinContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Get<OpenIdConnectResponse>(OpenIdConnectConstants.Environment.Response);
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectRequest"/> request in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectRequest"/>.</param>
        public static void SetOpenIdConnectRequest([NotNull] this IOwinContext context, OpenIdConnectRequest request) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            context.Set(OpenIdConnectConstants.Environment.Request, request);
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectResponse"/> response in the OWIN context.
        /// </summary>
        /// <param name="context">The OWIN context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectResponse"/>.</param>
        public static void SetOpenIdConnectResponse([NotNull] this IOwinContext context, OpenIdConnectResponse response) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            context.Set(OpenIdConnectConstants.Environment.Response, response);
        }

        /// <summary>
        /// Add information into the response environment that will cause the authentication
        /// middleware to return a forbidden response to the caller. This also changes the status
        /// code of the response to 403. The nature of that challenge varies greatly, and ranges
        /// from adding a response header or changing the 403 status code to a 302 redirect.
        /// </summary>
        /// <param name="manager">
        /// The authentication manager used to manage challenges.
        /// </param>
        /// <param name="properties">
        /// Additional arbitrary values which may be used by particular authentication types.
        /// </param>
        /// <param name="schemes">
        /// Identify which middleware should perform their alterations on the response. If
        /// the authenticationTypes is null or empty, that means the AuthenticationMode.Active
        /// middleware should perform their alterations on the response.
        /// </param>
        public static void Forbid(
            [NotNull] this IAuthenticationManager manager,
            [NotNull] AuthenticationProperties properties, [NotNull] params string[] schemes) {
            // Note: unlike ASP.NET Core's AuthenticationManager, Katana's manager doesn't natively support "forbidden responses".
            // To work around this limitation, this extension backports ASP.NET Core's ForbidAsync method to OWIN/Katana.

            if (manager == null) {
                throw new ArgumentNullException(nameof(manager));
            }

            if (properties == null) {
                throw new ArgumentNullException(nameof(properties));
            }

            if (schemes == null) {
                throw new ArgumentNullException(nameof(schemes));
            }

            // Note: the OWIN context is not exposed by IAuthenticationManager
            // but can be extracted from the default implementation using reflection.
            var context = manager.GetType()
                                 .GetField("_context", BindingFlags.Instance | BindingFlags.NonPublic)
                                ?.GetValue(manager) as IOwinContext;
            if (context == null) {
                throw new InvalidOperationException("This method can only be used with the default AuthenticationManager implementation.");
            }

            var challenge = manager.AuthenticationResponseChallenge;
            if (challenge == null) {
                manager.AuthenticationResponseChallenge = new AuthenticationResponseChallenge(schemes, properties);

                return;
            }

            // Concat the authentication schemes used by the prior
            // challenge with the schemes specified by the caller.
            var types = challenge.AuthenticationTypes.Concat(schemes).ToArray();

            if (properties != null && !ReferenceEquals(properties.Dictionary, challenge.Properties.Dictionary)) {
                foreach (var item in properties.Dictionary) {
                    challenge.Properties.Dictionary[item.Key] = item.Value;
                }
            }

            manager.AuthenticationResponseChallenge = new AuthenticationResponseChallenge(types, challenge.Properties);
        }

        /// <summary>
        /// Add information into the response environment that will cause the authentication
        /// middleware to return a forbidden response to the caller. This also changes the status
        /// code of the response to 403. The nature of that challenge varies greatly, and ranges
        /// from adding a response header or changing the 403 status code to a 302 redirect.
        /// </summary>
        /// <param name="manager">
        /// The authentication manager used to manage challenges.
        /// </param>
        /// <param name="schemes">
        /// Identify which middleware should perform their alterations on the response. If
        /// the authenticationTypes is null or empty, that means the AuthenticationMode.Active
        /// middleware should perform their alterations on the response.
        /// </param>
        public static void Forbid([NotNull] this IAuthenticationManager manager, [NotNull] params string[] schemes)
            => manager.Forbid(new AuthenticationProperties(), schemes);
    }
}
