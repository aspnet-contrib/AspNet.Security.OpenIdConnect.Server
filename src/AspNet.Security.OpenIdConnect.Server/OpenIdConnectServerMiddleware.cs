/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Security.DataHandler;
using Microsoft.AspNet.Security.DataProtection;
using Microsoft.AspNet.Security.Infrastructure;
using Microsoft.Framework.Logging;
using Microsoft.Framework.OptionsModel;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Authorization Server middleware component which is added to an OWIN pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
    /// extension method.
    /// </summary>
    public class OpenIdConnectServerMiddleware : AuthenticationMiddleware<OpenIdConnectServerOptions> {
        private readonly ILogger _logger;

        /// <summary>
        /// Authorization Server middleware component which is added to an OWIN pipeline. This constructor is not
        /// called by application code directly, instead it is added by calling the the IAppBuilder UseOpenIdConnectServer 
        /// extension method.
        /// </summary>
        public OpenIdConnectServerMiddleware(
            RequestDelegate next,
            IServiceProvider services,
            ILoggerFactory loggerFactory,
            IDataProtectionProvider dataProtectorProvider,
            IOptions<OpenIdConnectServerOptions> options,
            ConfigureOptions<OpenIdConnectServerOptions> configuration)
            : base(next, services, options, configuration) {
            _logger = loggerFactory.Create<OpenIdConnectServerMiddleware>();

            if (Options.Provider == null) {
                Options.Provider = new OpenIdConnectServerProvider();
            }

            if (Options.AuthorizationCodeFormat == null) {
                IDataProtector dataProtector = dataProtectorProvider.CreateDataProtector(
                    typeof(OpenIdConnectServerMiddleware).FullName,
                    "Authentication_Code", "v1");

                Options.AuthorizationCodeFormat = new TicketDataFormat(dataProtector);
            }

            if (Options.AccessTokenFormat == null) {
                IDataProtector dataProtector = dataProtectorProvider.CreateDataProtector(
                    "Microsoft.AspNet.Security.OAuth.OAuthBearerAuthenticationMiddleware",
                    "Bearer", "v1");

                Options.AccessTokenFormat = new TicketDataFormat(dataProtector);
            }

            if (Options.RefreshTokenFormat == null) {
                IDataProtector dataProtector = dataProtectorProvider.CreateDataProtector(
                    typeof(OpenIdConnectServerMiddleware).Namespace,
                    "Refresh_Token", "v1");

                Options.RefreshTokenFormat = new TicketDataFormat(dataProtector);
            }

            if (Options.AuthorizationCodeProvider == null) {
                Options.AuthorizationCodeProvider = new AuthenticationTokenProvider();
            }

            if (Options.AccessTokenProvider == null) {
                Options.AccessTokenProvider = new AuthenticationTokenProvider();
            }

            if (Options.RefreshTokenProvider == null) {
                Options.RefreshTokenProvider = new AuthenticationTokenProvider();
            }

            if (Options.SystemClock == null) {
                Options.SystemClock = new SystemClock();
            }

            if (Options.TokenHandler == null) {
                Options.TokenHandler = new JwtSecurityTokenHandler();
            }

            if (!Options.AuthorizationEndpointPath.HasValue) {
                throw new ArgumentException("options.AuthorizationEndpointPath must be provided. " +
                    "Make sure to use a custom value or remove the setter call to use the default value.",
                    "options.AuthorizationEndpointPath");
            }

            if (string.IsNullOrWhiteSpace(Options.Issuer)) {
                throw new ArgumentNullException("options.Issuer");
            }

            Uri issuer;
            if (!Uri.TryCreate(Options.Issuer, UriKind.Absolute, out issuer)) {
                throw new ArgumentException("options.Issuer must be a valid absolute URI.", "options.Issuer");
            }

            // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
            if (!string.IsNullOrWhiteSpace(issuer.Query) || !string.IsNullOrWhiteSpace(issuer.Fragment)) {
                throw new ArgumentException("options.Issuer must contain no query and no fragment parts.", "options.Issuer");
            }

            // Note: while the issuer parameter should be a HTTPS URI, making HTTPS mandatory
            // in AspNet.Security.OpenIdConnect.Server would prevent the end developer from
            // running the different samples in test environments, where HTTPS is often disabled.
            // To mitigate this issue, AllowInsecureHttp can be set to true to bypass the HTTPS check.
            // See http://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
            if (!Options.AllowInsecureHttp && string.Equals(issuer.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) {
                throw new ArgumentException("options.Issuer must be a HTTPS URI when " +
                    "options.AllowInsecureHttp is not set to true.", "options.Issuer");
            }

            if (Options.Issuer.EndsWith("/")) {
                // Remove the trailing slash to make concatenation easier in
                // OpenIdConnectServerHandler.InvokeConfigurationEndpointAsync.
                Options.Issuer = Options.Issuer.Substring(0, Options.Issuer.Length - 1);
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler. 
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<OpenIdConnectServerOptions> CreateHandler() {
            return new OpenIdConnectServerHandler(_logger);
        }
    }
}
