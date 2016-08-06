/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Builder {
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
        /// <param name="configuration">
        /// A delegate allowing to modify the options
        /// controlling the behavior of the OpenID Connect server.
        /// </param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIdConnectServerOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OpenIdConnectServerOptions();
            configuration(options);

            return app.UseMiddleware<OpenIdConnectServerMiddleware>(Options.Create(options));
        }

        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET pipeline.
        /// </summary>
        /// <param name="app">The web application builder.</param>
        /// <param name="options">The options controlling the behavior of the OpenID Connect server.</param>
        /// <returns>The application builder.</returns>
        public static IApplicationBuilder UseOpenIdConnectServer(
            [NotNull] this IApplicationBuilder app,
            [NotNull] OpenIdConnectServerOptions options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<OpenIdConnectServerMiddleware>(Options.Create(options));
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] X509Certificate2 certificate) {
            if (credentials == null) {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (!certificate.HasPrivateKey) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            return credentials.AddKey(new X509SecurityKey(certificate));
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
            [NotNull] this IList<SigningCredentials> credentials,
            [NotNull] Stream stream, [NotNull] string password) {
            return credentials.AddCertificate(stream, password, X509KeyStorageFlags.Exportable |
                                                                X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign the tokens issued by the OpenID Connect server.
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
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSha512Signature: {
                    // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
                    // where RSACryptoServiceProvider is still the default implementation and
                    // where custom implementations can be registered via CryptoConfig.
                    // To ensure the key size is always acceptable, replace it if necessary.
                    var rsa = RSA.Create();

                    if (rsa.KeySize < 2048) {
                        rsa.KeySize = 2048;
                    }

#if NET451
                    // Note: RSACng cannot be used as it's not available on Mono.
                    if (rsa.KeySize < 2048 && rsa is RSACryptoServiceProvider) {
                        rsa.Dispose();
                        rsa = new RSACryptoServiceProvider(2048);
                    }
#endif

                    if (rsa.KeySize < 2048) {
                        throw new InvalidOperationException("The ephemeral key generation failed.");
                    }

                    // Note: the RSA instance cannot be flowed as-is due to a bug in IdentityModel that disposes
                    // the underlying algorithm when it can be cast to RSACryptoServiceProvider. To work around
                    // this bug, the RSA public/private parameters are manually exported and re-imported when needed.
                    SecurityKey key;
#if NET451
                    if (rsa is RSACryptoServiceProvider) {
                        var parameters = rsa.ExportParameters(includePrivateParameters: true);
                        key = new RsaSecurityKey(parameters);
                        key.KeyId = key.GetKeyIdentifier();

                        // Dispose the algorithm instance.
                        rsa.Dispose();
                    }

                    else {
#endif
                        key = new RsaSecurityKey(rsa);
                        key.KeyId = key.GetKeyIdentifier();
#if NET451
                    }
#endif

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }

#if SUPPORTS_ECDSA
                case SecurityAlgorithms.EcdsaSha256Signature: {
                    // Generate a new ECDSA key using the P-256 curve.
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                    var key = new ECDsaSecurityKey(ecdsa);
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }

                case SecurityAlgorithms.EcdsaSha384Signature: {
                    // Generate a new ECDSA key using the P-384 curve.
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

                    var key = new ECDsaSecurityKey(ecdsa);
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }

                case SecurityAlgorithms.EcdsaSha512Signature: {
                    // Generate a new ECDSA key using the P-521 curve.
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);

                    var key = new ECDsaSecurityKey(ecdsa);
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }
#endif

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

            // When no key identifier can be retrieved from the security key, a value is automatically
            // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1)
            // when the key is bound to a X.509 certificate or from the public part of the signing key.
            if (string.IsNullOrEmpty(key.KeyId)) {
                key.KeyId = key.GetKeyIdentifier();
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature));

                return credentials;
            }

#if SUPPORTS_ECDSA
            // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256Signature));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha384Signature));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha512Signature));

                return credentials;
            }
#endif

            throw new InvalidOperationException("A signature algorithm cannot be automatically inferred from the signing key. " +
                                                "Consider using 'options.SigningCredentials.Add(SigningCredentials)' instead.");
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectRequest"/> instance
        /// associated with the current request from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectRequest"/> associated with the current request.</returns>
        public static OpenIdConnectRequest GetOpenIdConnectRequest([NotNull] this HttpContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            return feature.Request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectResponse"/> instance
        /// associated with the current response from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectResponse"/> associated with the current response.</returns>
        public static OpenIdConnectResponse GetOpenIdConnectResponse([NotNull] this HttpContext context) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            return feature.Response;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectRequest"/> request in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectRequest"/>.</param>
        public static void SetOpenIdConnectRequest([NotNull] this HttpContext context, OpenIdConnectRequest request) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            feature.Request = request;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectResponse"/> response in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectResponse"/>.</param>
        public static void SetOpenIdConnectResponse([NotNull] this HttpContext context, OpenIdConnectResponse response) {
            if (context == null) {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            feature.Response = response;
        }
    }
}
