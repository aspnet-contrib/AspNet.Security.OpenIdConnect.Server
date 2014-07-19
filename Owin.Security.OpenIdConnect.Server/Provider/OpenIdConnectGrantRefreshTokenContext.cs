// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Microsoft.Owin.Security.OpenIdConnect.Server {
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
