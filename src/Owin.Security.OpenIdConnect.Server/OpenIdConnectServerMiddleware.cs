/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Interop;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Authorization Server middleware component which is added to an OWIN pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
    /// extension method.
    /// </summary>
    public class OpenIdConnectServerMiddleware : AuthenticationMiddleware<OpenIdConnectServerOptions> {
        /// <summary>
        /// Authorization Server middleware component which is added to an OWIN pipeline. This constructor is not
        /// called by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
        /// extension method.
        /// </summary>
        public OpenIdConnectServerMiddleware(OwinMiddleware next, IAppBuilder app, OpenIdConnectServerOptions options)
            : base(next, options) {
            if (Options.HtmlEncoder == null) {
                throw new ArgumentException("The HTML encoder registered in the options " +
                                            "cannot be null.", nameof(options));
            }

            if (Options.Provider == null) {
                throw new ArgumentException("The authorization provider registered in " +
                                            "the options cannot be null.", nameof(options));
            }

            if (Options.RandomNumberGenerator == null) {
                throw new ArgumentException("The random number generator registered in " +
                                            "the options cannot be null.", nameof(options));
            }

            if (Options.SystemClock == null) {
                throw new ArgumentException("The system clock registered in the options " +
                                            "cannot be null.", nameof(options));
            }

            if (Options.Issuer != null) {
                if (!Options.Issuer.IsAbsoluteUri) {
                    throw new ArgumentException("The issuer registered in the options must be " +
                                                "a valid absolute URI.", nameof(options));
                }

                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!string.IsNullOrEmpty(Options.Issuer.Query) || !string.IsNullOrEmpty(Options.Issuer.Fragment)) {
                    throw new ArgumentException("The issuer registered in the options must contain no query " +
                                                "and no fragment parts.", nameof(options));
                }

                // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
                // in Owin.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!Options.AllowInsecureHttp && string.Equals(Options.Issuer.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    throw new ArgumentException("The issuer registered in the options must be a HTTPS URI when " +
                                                "AllowInsecureHttp is not set to true.", nameof(options));
                }
            }

            if (Options.Logger == null) {
                Options.Logger = new LoggerFactory().CreateLogger<OpenIdConnectServerMiddleware>();
            }

            if (Options.DataProtectionProvider == null) {
                // Create a new DI container and register
                // the data protection services.
                var services = new ServiceCollection();

                services.AddDataProtection(configuration => {
                    // Try to use the application name provided by
                    // the OWIN host as the application discriminator.
                    var discriminator = new AppProperties(app.Properties).AppName;

                    // When an application discriminator cannot be resolved from
                    // the OWIN host properties, generate a temporary identifier.
                    if (string.IsNullOrEmpty(discriminator)) {
                        discriminator = Guid.NewGuid().ToString();
                    }

                    configuration.ApplicationDiscriminator = discriminator;
                });

                var container = services.BuildServiceProvider();

                // Resolve a data protection provider from the services container.
                Options.DataProtectionProvider = container.GetRequiredService<IDataProtectionProvider>();
            }

            if (Options.AccessTokenFormat == null) {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationType, "Access_Token", "v1");

                Options.AccessTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (Options.AuthorizationCodeFormat == null) {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationType, "Authorization_Code", "v1");

                Options.AuthorizationCodeFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (Options.RefreshTokenFormat == null) {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationType, "Refresh_Token", "v1");

                Options.RefreshTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            // If no key has been explicitly added, use the fallback mode.
            if (Options.EncryptingCredentials.Count == 0 || Options.SigningCredentials.Count == 0) {
                var directory = OpenIdConnectServerHelpers.GetDefaultKeyStorageDirectory();
                Debug.Assert(directory != null);

                // Get a data protector from the services provider.
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationType, "Keys", "v1");

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
                            Options.Logger.LogDebug("An invalid/incompatible key was ignored: {Key}.", file.FullName);

                            continue;
                        }

                        if (string.Equals(usage, "Encryption", StringComparison.OrdinalIgnoreCase)) {
                            // Only add the encryption key if none has been explictly added.
                            if (Options.EncryptingCredentials.Count != 0) {
                                continue;
                            }

                            var algorithm = RSA.Create();
                            algorithm.ImportParameters(parameters.Value);

                            // Add the key to the encryption credentials list.
                            Options.EncryptingCredentials.AddKey(new RsaSecurityKey(algorithm));

                            Options.Logger.LogInformation("An existing key was automatically added to the " +
                                                          "encryption credentials list: {Key}.", file.FullName);
                        }

                        else if (string.Equals(usage, "Signing", StringComparison.OrdinalIgnoreCase)) {
                            // Only add the signing key if none has been explictly added.
                            if (Options.SigningCredentials.Count != 0) {
                                continue;
                            }

                            var algorithm = RSA.Create();
                            algorithm.ImportParameters(parameters.Value);

                            // Add the key to the signing credentials list.
                            Options.SigningCredentials.AddKey(new RsaSecurityKey(algorithm));

                            Options.Logger.LogInformation("An existing key was automatically added to the " +
                                                          "signing credentials list: {Key}.", file.FullName);
                        }
                    }
                }

                // If no encryption key has been found, generate and persist a new RSA key.
                if (Options.EncryptingCredentials.Count == 0) {
                    // Generate a new RSA key and export its public/private parameters.
                    var algorithm = OpenIdConnectServerHelpers.GenerateKey(size: 2048);
                    var parameters = algorithm.ExportParameters(/* includePrivateParameters: */ true);

                    // Generate a new file name for the key and determine its absolute path.
                    var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

                    using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                        // Encrypt the key using the data protector.
                        var bytes = OpenIdConnectServerHelpers.EncryptKey(protector, parameters, usage: "Encryption");

                        // Write the encrypted key to the file stream.
                        stream.Write(bytes, 0, bytes.Length);
                    }

                    Options.EncryptingCredentials.AddKey(new RsaSecurityKey(algorithm));

                    Options.Logger.LogInformation("A new RSA key was automatically generated, added to the " +
                                                  "encryption credentials list and persisted on the disk: {Path}.", path);
                }

                // If no signing key has been found, generate and persist a new RSA key.
                if (Options.SigningCredentials.Count == 0) {
                    // Generate a new RSA key and export its public/private parameters.
                    var algorithm = OpenIdConnectServerHelpers.GenerateKey(size: 2048);
                    var parameters = algorithm.ExportParameters(/* includePrivateParameters: */ true);

                    // Generate a new file name for the key and determine its absolute path.
                    var path = Path.Combine(directory.FullName, Guid.NewGuid().ToString() + ".key");

                    using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                        // Encrypt the key using the data protector.
                        var bytes = OpenIdConnectServerHelpers.EncryptKey(protector, parameters, usage: "Signing");

                        // Write the encrypted key to the file stream.
                        stream.Write(bytes, 0, bytes.Length);
                    }

                    Options.SigningCredentials.AddKey(new RsaSecurityKey(algorithm));

                    Options.Logger.LogInformation("A new RSA key was automatically generated, added to the " +
                                                  "signing credentials list and persisted on the disk: {Path}.", path);
                }
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler. 
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<OpenIdConnectServerOptions> CreateHandler() {
            return new OpenIdConnectServerHandler();
        }
    }
}
