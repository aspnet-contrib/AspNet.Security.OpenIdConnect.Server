/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
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

            // By default, enable AllowInsecureHttp in development/testing environments.
            var environment = app.ApplicationServices.GetRequiredService<IHostingEnvironment>();
            options.AllowInsecureHttp = environment.IsDevelopment() || environment.IsEnvironment("Testing");

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
        /// Adds a specific <see cref="X509Certificate2"/> to sign tokens issued by the OpenID Connect server.
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
        /// embedded resource to sign tokens issued by the OpenID Connect server.
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
        /// a stream to sign tokens issued by the OpenID Connect server.
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
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from the
        /// X509 machine store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] string thumbprint) {
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
        /// Adds a specific <see cref="SecurityKey"/> to sign tokens issued by the OpenID Connect server.
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
                // When no key identifier can be retrieved from the security key, a value is automatically
                // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1)
                // when the key is bound to a X509 certificate or from the public part of the RSA key.
                if (string.IsNullOrEmpty(key.KeyId)) {
                    var x509SecurityKey = key as X509SecurityKey;
                    if (x509SecurityKey != null) {
                        key.KeyId = x509SecurityKey.Certificate.Thumbprint;
                    }

                    var rsaSecurityKey = key as RsaSecurityKey;
                    if (rsaSecurityKey != null) {
                        // Note: if the RSA parameters are not attached to the signing key,
                        // extract them by calling ExportParameters on the RSA instance.
                        var parameters = rsaSecurityKey.Parameters;
                        if (parameters.Modulus == null) {
                            parameters = rsaSecurityKey.Rsa.ExportParameters(includePrivateParameters: false);
                            Debug.Assert(parameters.Modulus != null, "A null modulus was returned by RSA.ExportParameters()");
                        }

                        // Only use the 40 first chars of the base64url-encoded modulus.
                        key.KeyId = Base64UrlEncoder.Encode(parameters.Modulus);
                        key.KeyId = key.KeyId.Substring(0, Math.Min(key.KeyId.Length, 40)).ToUpperInvariant();
                    }
                }

                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256Signature)) {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

                return credentials;
            }

            throw new InvalidOperationException("The signing key type is not supported.");
        }

        /// <summary>
        /// Configures the OpenID Connect server to issue JWT access tokens.
        /// </summary>
        /// <param name="options">The options used to configure the OpenID Connect server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerOptions UseJwtTokens([NotNull] this OpenIdConnectServerOptions options) {
            options.AccessTokenHandler = new JwtSecurityTokenHandler();

            return options;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest([NotNull] this HttpContext context) {
            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            return feature.Request;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> request in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectRequest([NotNull] this HttpContext context, OpenIdConnectMessage request) {
            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            feature.Request = request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current response from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current response.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectResponse([NotNull] this HttpContext context) {
            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            return feature.Response;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectMessage"/> response in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="response">The ambient <see cref="OpenIdConnectMessage"/>.</param>
        public static void SetOpenIdConnectResponse([NotNull] this HttpContext context, OpenIdConnectMessage response) {
            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            feature.Response = response;
        }
    }
}
