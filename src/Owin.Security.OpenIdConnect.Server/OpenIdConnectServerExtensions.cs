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
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
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
                new LocalIdKeyIdentifierClause(certificate.Thumbprint.ToUpperInvariant()),
                new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5t, certificate.Thumbprint.ToUpperInvariant())
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
                throw new ArgumentException("The resource cannot be null or empty.", nameof(password));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
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
            [NotNull] this IList<EncryptingCredentials> credentials,
            [NotNull] Stream stream, [NotNull] string password) {
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
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
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
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
            }

            var certificate = OpenIdConnectServerHelpers.GetCertificate(StoreName.My, StoreLocation.CurrentUser, thumbprint) ??
                              OpenIdConnectServerHelpers.GetCertificate(StoreName.My, StoreLocation.LocalMachine, thumbprint);

            if (certificate == null) {
                throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
            }

            return credentials.AddCertificate(certificate);
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
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
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
        /// <param name="credentials">The encryption credentials.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddEphemeralKey([NotNull] this IList<EncryptingCredentials> credentials) {
            return credentials.AddEphemeralKey(SecurityAlgorithms.RsaOaepKeyWrap);
        }

        /// <summary>
        /// Adds a new ephemeral key used to decrypt the authorization requests received by the OpenID Connect server:
        /// the key is discarded when the application shuts down and authorization requests encrypted using this key
        /// cannot be decrypted when the key is lost. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="credentials">The encryption credentials.</param>
        /// <param name="algorithm">The algorithm associated with the encryption key.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddEphemeralKey(
            [NotNull] this IList<EncryptingCredentials> credentials, [NotNull] string algorithm) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(algorithm)) {
                throw new ArgumentException("The algorithm cannot be null or empty.", nameof(algorithm));
            }

            switch (algorithm) {
                case SecurityAlgorithms.RsaOaepKeyWrap:
                case SecurityAlgorithms.RsaV15KeyWrap: {
                    // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
                    // where RSACryptoServiceProvider is still the default implementation and
                    // where custom implementations can be registered via CryptoConfig.
                    // To ensure the key size is always acceptable, replace it if necessary.
                    var rsa = RSA.Create();

                    if (rsa.KeySize < 2048) {
                        rsa.KeySize = 2048;
                    }

                    // Note: RSACng cannot be used as it's not available on Mono.
                    if (rsa.KeySize < 2048 && rsa is RSACryptoServiceProvider) {
                        rsa.Dispose();
                        rsa = new RSACryptoServiceProvider(2048);
                    }

                    if (rsa.KeySize < 2048) {
                        throw new InvalidOperationException("The ephemeral key generation failed.");
                    }

                    var key = new RsaSecurityKey(rsa);

                    credentials.Add(new EncryptingCredentials(key, key.GetKeyIdentifier(), algorithm));

                    return credentials;
                }

                default:
                    throw new InvalidOperationException("The specified algorithm is not supported.");
            }
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
                credentials.Add(new EncryptingCredentials(key, key.GetKeyIdentifier(), SecurityAlgorithms.RsaOaepKeyWrap));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256Encryption)) {
                credentials.Add(new EncryptingCredentials(key, key.GetKeyIdentifier(), SecurityAlgorithms.Aes256Encryption));

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
                new LocalIdKeyIdentifierClause(certificate.Thumbprint.ToUpperInvariant()),
                new NamedKeySecurityKeyIdentifierClause(JwtHeaderParameterNames.X5t, certificate.Thumbprint.ToUpperInvariant())
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
                throw new ArgumentException("The resource cannot be null or empty.", nameof(password));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
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
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
            }

            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);

                return credentials.AddCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
            }
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the X.509
        /// user/machine store to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] string thumbprint) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
            }

            var certificate = OpenIdConnectServerHelpers.GetCertificate(StoreName.My, StoreLocation.CurrentUser, thumbprint) ??
                              OpenIdConnectServerHelpers.GetCertificate(StoreName.My, StoreLocation.LocalMachine, thumbprint);

            if (certificate == null) {
                throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
            }

            return credentials.AddCertificate(certificate);
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
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
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
        /// are automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddEphemeralKey([NotNull] this IList<SigningCredentials> credentials) {
            return credentials.AddEphemeralKey(SecurityAlgorithms.RsaSha256Signature);
        }

        /// <summary>
        /// Adds a new ephemeral key used to sign the tokens issued by the OpenID Connect server:
        /// the key is discarded when the application shuts down and tokens signed using this key
        /// are automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <param name="algorithm">The algorithm associated with the signing key.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddEphemeralKey(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] string algorithm) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(algorithm)) {
                throw new ArgumentException("The algorithm cannot be null or empty.", nameof(algorithm));
            }

            switch (algorithm) {
                case SecurityAlgorithms.RsaSha256Signature: {
                    // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
                    // where RSACryptoServiceProvider is still the default implementation and
                    // where custom implementations can be registered via CryptoConfig.
                    // To ensure the key size is always acceptable, replace it if necessary.
                    var rsa = RSA.Create();

                    if (rsa.KeySize < 2048) {
                        rsa.KeySize = 2048;
                    }

                    // Note: RSACng cannot be used as it's not available on Mono.
                    if (rsa.KeySize < 2048 && rsa is RSACryptoServiceProvider) {
                        rsa.Dispose();
                        rsa = new RSACryptoServiceProvider(2048);
                    }

                    if (rsa.KeySize < 2048) {
                        throw new InvalidOperationException("The ephemeral key generation failed.");
                    }

                    var key = new RsaSecurityKey(rsa);

                    credentials.Add(new SigningCredentials(key, algorithm,
                        SecurityAlgorithms.Sha256Digest, key.GetKeyIdentifier()));

                    return credentials;
                }

                default:
                    throw new InvalidOperationException("The specified algorithm is not supported.");
            }
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
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature,
                                                            SecurityAlgorithms.Sha256Digest, key.GetKeyIdentifier()));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature,
                                                            SecurityAlgorithms.Sha256Digest, key.GetKeyIdentifier()));

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

            return context.Get<OpenIdConnectRequest>(typeof(OpenIdConnectRequest).FullName);
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

            return context.Get<OpenIdConnectResponse>(typeof(OpenIdConnectResponse).FullName);
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

            context.Set(typeof(OpenIdConnectRequest).FullName, request);
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

            context.Set(typeof(OpenIdConnectResponse).FullName, response);
        }
    }
}
