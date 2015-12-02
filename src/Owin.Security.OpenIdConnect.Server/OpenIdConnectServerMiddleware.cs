/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;

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
                Options.Logger = app.CreateLogger<OpenIdConnectServerMiddleware>();
            }
            
            if (Options.AuthorizationCodeFormat == null) {
                Options.AuthorizationCodeFormat = app.CreateTicketFormat(
                    typeof(OpenIdConnectServerMiddleware).FullName,
                    Options.AuthenticationType, "Authentication_Code", "v1");
            }

            if (Options.AccessTokenFormat == null) {
                Options.AccessTokenFormat = app.CreateTicketFormat(
                    typeof(OpenIdConnectServerMiddleware).FullName,
                    Options.AuthenticationType, "Access_Token", "v1");
            }

            if (Options.RefreshTokenFormat == null) {
                Options.RefreshTokenFormat = app.CreateTicketFormat(
                    typeof(OpenIdConnectServerMiddleware).Namespace,
                    Options.AuthenticationType, "Refresh_Token", "v1");
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
