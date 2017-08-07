/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Owin;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Interop;

namespace Owin.Security.OpenIdConnect.Server
{
    /// <summary>
    /// Provides the entry point necessary to register the
    /// OpenID Connect server in an OWIN/Katana pipeline.
    /// </summary>
    public class OpenIdConnectServerMiddleware : AuthenticationMiddleware<OpenIdConnectServerOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIdConnectServerMiddleware"/> class.
        /// </summary>
        public OpenIdConnectServerMiddleware(
            [NotNull] OwinMiddleware next,
            [NotNull] IDictionary<string, object> properties,
            [NotNull] OpenIdConnectServerOptions options)
            : base(next, options)
        {
            if (Options.Provider == null)
            {
                throw new ArgumentException("The authorization provider registered in the options cannot be null.", nameof(options));
            }

            if (Options.HtmlEncoder == null)
            {
                throw new ArgumentException("The HTML encoder registered in the options cannot be null.", nameof(options));
            }

            if (Options.SystemClock == null)
            {
                throw new ArgumentException("The system clock registered in the options cannot be null.", nameof(options));
            }

            if (Options.Issuer != null)
            {
                if (!Options.Issuer.IsAbsoluteUri)
                {
                    throw new ArgumentException("The issuer registered in the options must be a valid absolute URI.", nameof(options));
                }

                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!string.IsNullOrEmpty(Options.Issuer.Query) || !string.IsNullOrEmpty(Options.Issuer.Fragment))
                {
                    throw new ArgumentException("The issuer registered in the options must contain " +
                                                "no query and no fragment parts.", nameof(options));
                }

                // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
                // in Owin.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!Options.AllowInsecureHttp && string.Equals(Options.Issuer.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException("The issuer registered in the options must be a HTTPS URI when " +
                                                "AllowInsecureHttp is not set to true.", nameof(options));
                }
            }

            if (Options.AuthenticationMode == AuthenticationMode.Active)
            {
                throw new ArgumentException("Automatic authentication cannot be used with " +
                                            "the OpenID Connect server middleware.", nameof(options));
            }

            // Ensure at least one signing certificate/key was registered if an access token handler was registered.
            if (Options.AccessTokenHandler != null && Options.SigningCredentials.Count == 0)
            {
                throw new ArgumentException(
                    "At least one signing key must be registered when using JWT as the access token format. " +
                    "Consider registering a X.509 certificate using 'options.SigningCredentials.AddCertificate()' " +
                    "or call 'options.SigningCredentials.AddEphemeralKey()' to use an ephemeral key.", nameof(options));
            }

            if (Options.Logger == null)
            {
                options.Logger = NullLogger.Instance;
            }

            if (Options.DataProtectionProvider == null)
            {
                // Use the application name provided by the OWIN host as the Data Protection discriminator.
                // If the application name cannot be resolved, throw an invalid operation exception.
                var discriminator = new AppProperties(properties).AppName;
                if (string.IsNullOrEmpty(discriminator))
                {
                    throw new InvalidOperationException(
                        "The application name cannot be resolved from the OWIN application builder. " +
                        "Consider manually setting the 'DataProtectionProvider' property in the " +
                        "options using 'DataProtectionProvider.Create([unique application name])'.");
                }

                Options.DataProtectionProvider = DataProtectionProvider.Create(discriminator);
            }

            if (Options.AccessTokenFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerHandler),
                    nameof(Options.AccessTokenFormat), Options.AuthenticationType);

                Options.AccessTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (Options.AuthorizationCodeFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerHandler),
                    nameof(Options.AuthorizationCodeFormat), Options.AuthenticationType);

                Options.AuthorizationCodeFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (Options.RefreshTokenFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdConnectServerHandler),
                    nameof(Options.RefreshTokenFormat), Options.AuthenticationType);

                Options.RefreshTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            var environment = new AppProperties(properties).Get<string>("host.AppMode");
            if (Options.AllowInsecureHttp && !string.Equals(environment, "Development", StringComparison.OrdinalIgnoreCase))
            {
                Options.Logger.LogWarning("Disabling the transport security requirement is not recommended in production. " +
                                          "Consider setting 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'false' " +
                                          "to prevent the OpenID Connect server middleware from serving non-HTTPS requests.");
            }
        }

        /// <summary>
        /// Returns a new <see cref="OpenIdConnectServerHandler"/> instance.
        /// </summary>
        /// <returns>A new instance of the <see cref="OpenIdConnectServerHandler"/> class.</returns>
        protected override AuthenticationHandler<OpenIdConnectServerOptions> CreateHandler()
        {
            return new OpenIdConnectServerHandler();
        }
    }
}
