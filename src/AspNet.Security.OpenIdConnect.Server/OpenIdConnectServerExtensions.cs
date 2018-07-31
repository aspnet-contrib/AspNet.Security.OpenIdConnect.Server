/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Provides extension methods allowing to easily register an
    /// ASP.NET Core-powered OpenID Connect server and to retrieve
    /// various OpenID Connect primitives from the ASP.NET Core environment.
    /// </summary>
    public static class OpenIdConnectServerExtensions
    {
        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOpenIdConnectServer([NotNull] this AuthenticationBuilder builder)
            => builder.AddOpenIdConnectServer(OpenIdConnectServerDefaults.AuthenticationScheme);

        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">
        /// A delegate allowing to modify the options
        /// controlling the behavior of the OpenID Connect server.
        /// </param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOpenIdConnectServer(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<OpenIdConnectServerOptions> configuration)
            => builder.AddOpenIdConnectServer(OpenIdConnectServerDefaults.AuthenticationScheme, configuration);

        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOpenIdConnectServer(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme)
            => builder.AddOpenIdConnectServer(scheme, options => { });

        /// <summary>
        /// Adds a new OpenID Connect server instance in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">
        /// A delegate allowing to modify the options
        /// controlling the behavior of the OpenID Connect server.
        /// </param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOpenIdConnectServer(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
            [NotNull] Action<OpenIdConnectServerOptions> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (string.IsNullOrEmpty(scheme))
            {
                throw new ArgumentException("The scheme cannot be null or empty.", nameof(scheme));
            }

            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectServerOptions>,
                                            OpenIdConnectServerInitializer>());

            return builder.AddScheme<OpenIdConnectServerOptions, OpenIdConnectServerHandler>(scheme, configuration);
        }

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="certificate">The certificate used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] X509Certificate2 certificate)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (certificate.NotBefore > DateTime.Now)
            {
                throw new InvalidOperationException("The specified certificate is not yet valid.");
            }

            if (certificate.NotAfter < DateTime.Now)
            {
                throw new InvalidOperationException("The specified certificate is no longer valid.");
            }

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("The specified certificate doesn't contain the required private key.");
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
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password)
            => credentials.AddCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);

        /// <summary>
        /// Adds a specific <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddCertificate(
            [NotNull] this IList<SigningCredentials> credentials,
            [NotNull] Assembly assembly, [NotNull] string resource,
            [NotNull] string password, X509KeyStorageFlags flags)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (assembly == null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
            }

            using (var stream = assembly.GetManifestResourceStream(resource))
            {
                if (stream == null)
                {
                    throw new InvalidOperationException("The certificate was not found in the specified assembly.");
                }

                return credentials.AddCertificate(stream, password, flags);
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
            [NotNull] Stream stream, [NotNull] string password)
            => credentials.AddCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);

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
            [NotNull] string password, X509KeyStorageFlags flags)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
            }

            using (var buffer = new MemoryStream())
            {
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
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] string thumbprint)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
            }

            var certificate = OpenIdConnectServerHelpers.GetCertificate(StoreName.My, StoreLocation.CurrentUser, thumbprint) ??
                              OpenIdConnectServerHelpers.GetCertificate(StoreName.My, StoreLocation.LocalMachine, thumbprint);

            if (certificate == null)
            {
                throw new InvalidOperationException("The certificate corresponding to the specified thumbprint was not found.");
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
            [NotNull] string thumbprint, StoreName name, StoreLocation location)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
            }

            var certificate = OpenIdConnectServerHelpers.GetCertificate(name, location, thumbprint);
            if (certificate == null)
            {
                throw new InvalidOperationException("The certificate corresponding to the specified thumbprint was not found.");
            }

            return credentials.AddCertificate(certificate);
        }

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development certificate
        /// used to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddDevelopmentCertificate(
            [NotNull] this IList<SigningCredentials> credentials)
        {
            return credentials.AddDevelopmentCertificate(new X500DistinguishedName("CN=OpenID Connect Server"));
        }

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development certificate
        /// used to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddDevelopmentCertificate(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] X500DistinguishedName subject)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (subject == null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            // Try to retrieve the development certificate from the specified store.
            // If a certificate was found but is not yet or no longer valid, remove it
            // from the store before creating and persisting a new signing certificate.
            var certificate = OpenIdConnectServerHelpers.GetDevelopmentCertificate(subject);
            if (certificate != null && (certificate.NotBefore > DateTime.Now || certificate.NotAfter < DateTime.Now))
            {
                OpenIdConnectServerHelpers.RemoveDevelopmentCertificate(certificate);
                certificate = null;
            }

#if SUPPORTS_CERTIFICATE_GENERATION
            // If no appropriate certificate can be found, generate
            // and persist a new certificate in the specified store.
            if (certificate == null)
            {
                certificate = OpenIdConnectServerHelpers.GenerateDevelopmentCertificate(subject);
                OpenIdConnectServerHelpers.PersistDevelopmentCertificate(certificate);
            }

            return credentials.AddCertificate(certificate);
#else
            throw new PlatformNotSupportedException("X.509 certificate generation is not supported on this platform.");
#endif
        }

        /// <summary>
        /// Adds a new ephemeral key used to sign the tokens issued by the OpenID Connect server:
        /// the key is discarded when the application shuts down and tokens signed using this key
        /// are automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddEphemeralKey([NotNull] this IList<SigningCredentials> credentials)
        {
            return credentials.AddEphemeralKey(SecurityAlgorithms.RsaSha256);
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
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] string algorithm)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentException("The algorithm cannot be null or empty.", nameof(algorithm));
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSha512Signature:
                {
                    var key = new RsaSecurityKey(OpenIdConnectServerHelpers.GenerateRsaKey(2048));
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }

#if SUPPORTS_ECDSA
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                {
                    // Generate a new ECDSA key using the P-256 curve.
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                    var key = new ECDsaSecurityKey(ecdsa);
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                {
                    // Generate a new ECDSA key using the P-384 curve.
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

                    var key = new ECDsaSecurityKey(ecdsa);
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                {
                    // Generate a new ECDSA key using the P-521 curve.
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);

                    var key = new ECDsaSecurityKey(ecdsa);
                    key.KeyId = key.GetKeyIdentifier();

                    credentials.Add(new SigningCredentials(key, algorithm));

                    return credentials;
                }
#else
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.EcdsaSha512Signature:
                    throw new PlatformNotSupportedException("ECDSA signing keys are not supported on this platform.");
#endif

                default: throw new InvalidOperationException("The specified algorithm is not supported.");
            }
        }

        /// <summary>
        /// Adds a specific <see cref="SecurityKey"/> to encrypt the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The encryption credentials.</returns>
        public static IList<EncryptingCredentials> AddKey(
            [NotNull] this IList<EncryptingCredentials> credentials, [NotNull] SecurityKey key)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW))
            {
                credentials.Add(new EncryptingCredentials(key, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));

                return credentials;
            }

            throw new InvalidOperationException("An encryption algorithm cannot be automatically inferred from the encrypting key. " +
                                                "Consider using 'options.EncryptingCredentials.Add(EncryptingCredentials)' instead.");
        }

        /// <summary>
        /// Adds a specific <see cref="SecurityKey"/> to sign the tokens issued by the OpenID Connect server.
        /// </summary>
        /// <param name="credentials">The options used to configure the OpenID Connect server.</param>
        /// <param name="key">The key used to sign security tokens issued by the server.</param>
        /// <returns>The signing credentials.</returns>
        public static IList<SigningCredentials> AddKey(
            [NotNull] this IList<SigningCredentials> credentials, [NotNull] SecurityKey key)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // If the signing key is an asymmetric security key, ensure it has a private key.
            if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
                asymmetricSecurityKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException("The asymmetric signing key doesn't contain the required private key.");
            }

            // When no key identifier can be retrieved from the security key, a value is automatically
            // inferred from the hexadecimal representation of the certificate thumbprint (SHA-1)
            // when the key is bound to a X.509 certificate or from the public part of the signing key.
            if (string.IsNullOrEmpty(key.KeyId))
            {
                key.KeyId = key.GetKeyIdentifier();
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
            {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
            {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

                return credentials;
            }

#if SUPPORTS_ECDSA
            // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256))
            {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384))
            {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha384));

                return credentials;
            }

            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
            {
                credentials.Add(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha512));

                return credentials;
            }
#else
            else if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
                     key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
                     key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
            {
                throw new PlatformNotSupportedException("ECDSA signing keys are not supported on this platform.");
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
        public static OpenIdConnectRequest GetOpenIdConnectRequest([NotNull] this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Features.Get<OpenIdConnectServerFeature>()?.Request;
        }

        /// <summary>
        /// Retrieves the <see cref="OpenIdConnectResponse"/> instance
        /// associated with the current response from the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <returns>The <see cref="OpenIdConnectResponse"/> associated with the current response.</returns>
        public static OpenIdConnectResponse GetOpenIdConnectResponse([NotNull] this HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.Features.Get<OpenIdConnectServerFeature>()?.Response;
        }

        /// <summary>
        /// Inserts the ambient <see cref="OpenIdConnectRequest"/> request in the ASP.NET context.
        /// </summary>
        /// <param name="context">The ASP.NET context.</param>
        /// <param name="request">The ambient <see cref="OpenIdConnectRequest"/>.</param>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static void SetOpenIdConnectRequest([NotNull] this HttpContext context, OpenIdConnectRequest request)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null)
            {
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
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static void SetOpenIdConnectResponse([NotNull] this HttpContext context, OpenIdConnectResponse response)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var feature = context.Features.Get<OpenIdConnectServerFeature>();
            if (feature == null)
            {
                feature = new OpenIdConnectServerFeature();

                context.Features.Set(feature);
            }

            feature.Response = response;
        }
    }
}
