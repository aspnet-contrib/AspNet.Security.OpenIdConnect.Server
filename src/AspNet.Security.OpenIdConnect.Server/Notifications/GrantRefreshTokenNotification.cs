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
    /// Provides context information used when granting an OpenIdConnect refresh token.
    /// </summary>
    public sealed class GrantRefreshTokenNotification : BaseValidatingTicketNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="GrantRefreshTokenNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tokenRequest"></param>
        /// <param name="ticket"></param>
        internal GrantRefreshTokenNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage tokenRequest,
            AuthenticationTicket ticket)
            : base(context, options, ticket) {
        }

        /// <summary>
        /// The OpenIdConnect client id.
        /// </summary>
        public string ClientId {
            get { return TokenRequest.ClientId; }
        }

        /// <summary>
        /// Gets the token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }
    }
}
