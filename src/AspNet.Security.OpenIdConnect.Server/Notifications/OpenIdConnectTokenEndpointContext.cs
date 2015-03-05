/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when processing an OpenIdConnect token request.
    /// </summary>
    public sealed class OpenIdConnectTokenEndpointContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectTokenEndpointContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="tokenRequest"></param>
        internal OpenIdConnectTokenEndpointContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage tokenRequest)
            : base(context, options) {
            if (ticket == null) {
                throw new ArgumentNullException(nameof(ticket));
            }

            Principal = ticket.Principal;
            Properties = ticket.Properties;
            TokenRequest = tokenRequest;
            TokenIssued = Principal != null;
        }

        /// <summary>
        /// Gets the principal of the resource owner.
        /// </summary>
        public ClaimsPrincipal Principal { get; private set; }

        /// <summary>
        /// Dictionary containing the state of the authentication session.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }

        /// <summary>
        /// Gets information about the token endpoint request. 
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; set; }

        /// <summary>
        /// Gets whether or not the token should be issued.
        /// </summary>
        public bool TokenIssued { get; private set; }

        /// <summary>
        /// Issues the token.
        /// </summary>
        /// <param name="principal"></param>
        /// <param name="properties"></param>
        public void Issue(ClaimsPrincipal principal, AuthenticationProperties properties) {
            Principal = principal;
            Properties = properties;
            TokenIssued = true;
        }
    }
}
