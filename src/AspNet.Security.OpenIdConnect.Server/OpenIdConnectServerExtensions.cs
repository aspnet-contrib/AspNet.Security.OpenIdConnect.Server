/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Features;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Microsoft.AspNet.Builder {
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
            [NotNull] Action<OpenIdConnectServerBuilder> configuration) {
            var builder = new OpenIdConnectServerBuilder(app);

            // By default, enable AllowInsecureHttp in development/testing environments.
            var environment = app.ApplicationServices.GetRequiredService<IHostingEnvironment>();
            builder.Options.AllowInsecureHttp = environment.IsDevelopment() || environment.IsEnvironment("Testing");

            configuration(builder);

            if (builder.Options == null) {
                throw new ArgumentException($"The '{nameof(builder.Options)}' property cannot be null.", nameof(builder));
            }

            // If no key has been explicitly added, use the fallback mode.
            if (builder.Options.SigningCredentials.Count == 0) {
                var directory = OpenIdConnectServerHelpers.GetDefaultKeyStorageDirectory();

                // Ensure the directory exists.
                if (!directory.Exists) {
                    directory.Create();
                    directory.Refresh();
                }

                builder.UseKeys(directory);
            }

            return app.UseMiddleware<OpenIdConnectServerMiddleware>(builder.Options);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseCertificate(
            [NotNull] this OpenIdConnectServerBuilder builder,
            [NotNull] X509Certificate2 certificate) {
            if (!certificate.HasPrivateKey) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            return builder.UseKey(new X509SecurityKey(certificate));
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseCertificate(
            [NotNull] this OpenIdConnectServerBuilder builder,
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password) {
            using (var stream = assembly.GetManifestResourceStream(resource)) {
                if (stream == null) {
                    throw new InvalidOperationException("The certificate was not found in the given assembly.");
                }

                return builder.UseCertificate(stream, password);
            }
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseCertificate(
            [NotNull] this OpenIdConnectServerBuilder builder,
            [NotNull] Stream stream, [NotNull] string password) {
            return builder.UseCertificate(stream, password, X509KeyStorageFlags.Exportable |
                                                                  X509KeyStorageFlags.MachineKeySet);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> contained in
        /// a stream to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseCertificate(
            [NotNull] this OpenIdConnectServerBuilder builder,
            [NotNull] Stream stream, [NotNull] string password, X509KeyStorageFlags flags) {
            using (var buffer = new MemoryStream()) {
                stream.CopyTo(buffer);

                return builder.UseCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
            }
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// X509 machine store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseCertificate(
            [NotNull] this OpenIdConnectServerBuilder builder, [NotNull] string thumbprint) {
            return builder.UseCertificate(thumbprint, StoreName.My, StoreLocation.LocalMachine);
        }

        /// <summary>
        /// Uses a specific <see cref="X509Certificate2"/> retrieved from the
        /// given X509 store to sign tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X509 store.</param>
        /// <param name="name">The name of the X509 store.</param>
        /// <param name="location">The location of the X509 store.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseCertificate(
            [NotNull] this OpenIdConnectServerBuilder builder,
            [NotNull] string thumbprint, StoreName name, StoreLocation location) {
            var store = new X509Store(name, location);

            try {
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                var certificate = certificates.OfType<X509Certificate2>().SingleOrDefault();
                if (certificate == null) {
                    throw new InvalidOperationException("The certificate corresponding to the given thumbprint was not found.");
                }

                return builder.UseCertificate(certificate);
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
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseKey(
            [NotNull] this OpenIdConnectServerBuilder builder, [NotNull] SecurityKey key) {
            builder.Options.SigningCredentials.Add(new SigningCredentials(key,
                SecurityAlgorithms.RsaSha256Signature,
                SecurityAlgorithms.Sha256Digest));

            return builder;
        }

        /// <summary>
        /// Uses the <see cref="RsaSecurityKey"/>s stored in the given directory.
        /// Note: this extension will automatically ignore incompatible keys and
        /// create a new RSA key if none has been previously added.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="directory">The directory containing the encrypted keys.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseKeys(
            [NotNull] this OpenIdConnectServerBuilder builder, [NotNull] DirectoryInfo directory) {
            // Gets a data protector from the services provider.
            var protector = builder.Builder.ApplicationServices.GetDataProtector(
                typeof(OpenIdConnectServerMiddleware).Namespace,
                builder.Options.AuthenticationScheme, "Signing_Credentials", "v1");

            return builder.UseKeys(directory, protector);
        }

        /// <summary>
        /// Uses the <see cref="RsaSecurityKey"/>s stored in the given directory.
        /// Note: this extension will automatically ignore incompatible keys and
        /// create a new RSA key if none has been previously added.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <param name="directory">The directory containing the encrypted keys.</param>
        /// <param name="protector">The data protector used to decrypt the key.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseKeys(
            [NotNull] this OpenIdConnectServerBuilder builder,
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

                    builder.UseKey(new RsaSecurityKey(parameters.Value));
                }
            }

            // If no signing key has been found, generate and persist a new RSA key.
            if (builder.Options.SigningCredentials.Count == 0) {
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

                builder.UseKey(new RsaSecurityKey(parameters));
            }

            return builder;
        }

        /// <summary>
        /// Configures the OpenID Connect server to issue opaque access tokens produced by the data protection block.
        /// Opaque tokens cannot be read by client applications or resource servers if they don't share identical keys.
        /// Note: you can use the validation/introspection endpoint to determine token status and metadata directly on the authorization server.
        /// </summary>
        /// <param name="builder">The options used to configure the OpenID Connect server.</param>
        /// <returns>The options used to configure the OpenID Connect server.</returns>
        public static OpenIdConnectServerBuilder UseOpaqueTokens([NotNull] this OpenIdConnectServerBuilder builder) {
            builder.Options.AccessTokenHandler = null;

            return builder;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectMessage"/> instance
        /// associated with the current request from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectMessage"/> associated with the current request.</returns>
        public static OpenIdConnectMessage GetOpenIdConnectRequest([NotNull] this HttpContext context) {
            var feature = context.Features.Get<IOpenIdConnectServerFeature>();
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
            var feature = context.Features.Get<IOpenIdConnectServerFeature>();
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
            var feature = context.Features.Get<IOpenIdConnectServerFeature>();
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
            var feature = context.Features.Get<IOpenIdConnectServerFeature>();
            if (feature == null) {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            feature.Response = response;
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
    }
}
