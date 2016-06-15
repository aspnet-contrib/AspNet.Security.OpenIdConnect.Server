/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AspNet.Security.OpenIdConnect.Server {
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
        public OpenIdConnectServerMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OpenIdConnectServerOptions> options,
            [NotNull] IHostingEnvironment environment,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] IDistributedCache cache,
            [NotNull] HtmlEncoder htmlEncoder,
            [NotNull] UrlEncoder urlEncoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, urlEncoder) {
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
                // in AspNet.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!Options.AllowInsecureHttp && string.Equals(Options.Issuer.Scheme, "http", StringComparison.OrdinalIgnoreCase)) {
                    throw new ArgumentException("The issuer registered in the options must be a HTTPS URI when " +
                                                "AllowInsecureHttp is not set to true.", nameof(options));
                }
            }

            if (Options.DataProtectionProvider == null) {
                Options.DataProtectionProvider = dataProtectionProvider;
            }

            if (Options.AccessTokenFormat == null) {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Access_Token", "v1");

                Options.AccessTokenFormat = new TicketDataFormat(protector);
            }

            if (Options.AuthorizationCodeFormat == null) {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Authentication_Code", "v1");

                Options.AuthorizationCodeFormat = new TicketDataFormat(protector);
            }

            if (Options.RefreshTokenFormat == null) {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Refresh_Token", "v1");

                Options.RefreshTokenFormat = new TicketDataFormat(protector);
            }

            if (Options.Cache == null) {
                Options.Cache = cache;
            }

            if (Options.HtmlEncoder == null) {
                Options.HtmlEncoder = htmlEncoder;
            }

            if (Options.AllowInsecureHttp && environment.IsProduction()) {
                Logger.LogWarning("Disabling the transport security requirement is not recommended on production. " +
                                  "Consider setting 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'false' " +
                                  "to prevent the OpenID Connect server middleware from serving non-HTTPS requests.");
            }

            // If no key has been explicitly added, use the fallback mode.
            if (Options.SigningCredentials.Count == 0) {
                // When detecting a non-development environment, log a warning to inform the developer
                // that registering a X.509 certificate is recommended when going live.
                if (environment.IsProduction()) {
                    Logger.LogWarning("No explicit signing credentials have been registered. " +
                                      "Using a X.509 certificate stored in the machine store " +
                                      "is recommended for production environments.");
                }

                var directory = OpenIdConnectServerHelpers.GetDefaultKeyStorageDirectory();
                if (directory == null) {
                    Logger.LogWarning("No suitable directory can be found to store the RSA keys." +
                                      "Using a X.509 certificate stored in the machine store " +
                                      "is recommended for production environments.");

                    return;
                }

                // Get a data protector from the services provider.
                var protector = dataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerMiddleware),
                    Options.AuthenticationScheme, "Keys", "v1");

                // Note: all the exceptions thrown when enumerating
                // existing keys or generating new ones must be caught.
                try {
                    foreach (var key in OpenIdConnectServerHelpers.GetKeys(directory)) {
                        // Extract the key material using the data protector.
                        // Ignore the key if the decryption process failed.
                        string usage;
                        var parameters = OpenIdConnectServerHelpers.DecryptKey(protector, key.Value, out usage);
                        if (parameters == null) {
                            Logger.LogDebug("An invalid/incompatible key was ignored: {Key}.", key.Key);

                            continue;
                        }

                        // Only add the key if it corresponds to the intended usage.
                        if (!string.Equals(usage, "Signing", StringComparison.OrdinalIgnoreCase)) {
                            continue;
                        }

                        // Add the key to the signing credentials list.
                        Options.SigningCredentials.AddKey(new RsaSecurityKey(parameters.Value));

                        Logger.LogInformation("An existing key was automatically added to the " +
                                              "signing credentials list: {Key}.", key.Key);
                    }
                }

                catch (Exception exception) {
                    Logger.LogDebug("An error ocurred when retrieving the keys stored " +
                                    "on the disk: {Exception}.", exception.ToString());
                }

                // Note: all the exceptions thrown when enumerating
                // existing keys or generating new ones must be caught.
                try {
                    // If no signing key has been found, generate and persist a new RSA key.
                    if (Options.SigningCredentials.Count == 0) {
                        // Generate a new RSA key and export its public/private parameters.
                        var provider = OpenIdConnectServerHelpers.GenerateKey(size: 2048);
                        var parameters = provider.ExportParameters(/* includePrivateParameters */ true);

                        // Add the signing key to the credentials list before trying to persist it on the disk.
                        Options.SigningCredentials.AddKey(new RsaSecurityKey(parameters));

                        try {
                            // Encrypt the key using the data protector and try to persist it on the disk.
                            var key = OpenIdConnectServerHelpers.EncryptKey(protector, parameters, usage: "Signing");
                            var path = OpenIdConnectServerHelpers.PersistKey(directory, key);

                            Logger.LogInformation("A new RSA key was automatically generated, added to the " +
                                                  "signing credentials list and persisted on the disk: {Path}.", path);
                        }

                        catch (Exception exception) {
                            Logger.LogWarning("An error ocurred when persisting a new key on the disk: {Exception}. " +
                                              "The key will be kept in memory and will be lost when the " +
                                              "application shuts down or restarts.", exception.ToString());
                        }
                    }
                }

                catch (Exception exception) {
                    Logger.LogDebug("An error ocurred when generating a new key: {Exception}.", exception.ToString());
                }
            }

            if (Options.SigningCredentials.Count == 0) {
                throw new ArgumentException("At least one signing key must be registered.", nameof(options));
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
