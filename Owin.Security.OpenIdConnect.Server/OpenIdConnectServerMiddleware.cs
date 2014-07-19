// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
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
            OwinMiddleware next,
            IAppBuilder app,
            OpenIdConnectServerOptions options)
            : base(next, options) {
            _logger = app.CreateLogger<OpenIdConnectServerMiddleware>();

            if (Options.Provider == null) {
                Options.Provider = new OpenIdConnectServerProvider();
            }

            if (Options.AuthorizationCodeFormat == null) {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(OpenIdConnectServerMiddleware).FullName,
                    "Authentication_Code", "v1");

                Options.AuthorizationCodeFormat = new TicketDataFormat(dataProtector);
            }

            if (Options.AccessTokenFormat == null) {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(OpenIdConnectServerMiddleware).Namespace,
                    "Access_Token", "v1");

                Options.AccessTokenFormat = new TicketDataFormat(dataProtector);
            }

            if (Options.RefreshTokenFormat == null) {
                IDataProtector dataProtector = app.CreateDataProtector(
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

            if (Options.ServerClaimsMapper == null) {
                throw new ArgumentNullException("options.ServerClaimsMapper");
            }

            if (Options.SigningCredentials == null) {
                throw new ArgumentNullException("options.SigningCredentials");
            }

            if (string.IsNullOrWhiteSpace(Options.IssuerName)) {
                throw new ArgumentException("options.IssuerName");
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
