/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when granting an OpenIdConnect refresh token.
    /// </summary>
    public class OpenIdConnectGrantRefreshTokenContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantRefreshTokenContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="clientId"></param>
        public OpenIdConnectGrantRefreshTokenContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            string clientId) : base(context, options, ticket) {
            ClientId = clientId;
        }

        /// <summary>
        /// The OpenIdConnect client id.
        /// </summary>
        public string ClientId { get; private set; }
    }
}
