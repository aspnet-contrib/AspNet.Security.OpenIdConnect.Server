/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
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
            if (Options.RandomNumberGenerator == null) {
                throw new ArgumentNullException("options.RandomNumberGenerator");
            }

            if (Options.Provider == null) {
                throw new ArgumentNullException("options.Provider");
            }
            
            if (Options.SystemClock == null) {
                throw new ArgumentNullException("options.SystemClock");
            }

            if (Options.Issuer != null) {
                if (!Options.Issuer.IsAbsoluteUri) {
                    throw new ArgumentException("options.Issuer must be a valid absolute URI.", "options.Issuer");
                }

                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!string.IsNullOrEmpty(Options.Issuer.Query) || !string.IsNullOrEmpty(Options.Issuer.Fragment)) {
                    throw new ArgumentException("options.Issuer must contain no query and no fragment parts.", "options.Issuer");
                }

                // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
                // in Owin.Security.OpenIdConnect.Server would prevent the end developer from
                // running the different samples in test environments, where HTTPS is often disabled.
                // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
                // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
                if (!Options.AllowInsecureHttp && string.Equals(Options.Issuer.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                    throw new ArgumentException("options.Issuer must be a HTTPS URI when " +
                        "options.AllowInsecureHttp is not set to true.", "options.Issuer");
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
