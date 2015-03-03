/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when handling an OpenIdConnect authorization code grant.
    /// </summary>
    public sealed class OpenIdConnectGrantAuthorizationCodeContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantAuthorizationCodeContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tokenRequest"></param>
        /// <param name="ticket"></param>
        internal OpenIdConnectGrantAuthorizationCodeContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage tokenRequest,
            AuthenticationTicket ticket) : base(context, options, ticket) {
            TokenRequest = tokenRequest;
        }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }
    }
}
