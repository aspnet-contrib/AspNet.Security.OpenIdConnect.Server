/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the token revocation endpoint.
    /// </summary>
    public class HandleRevocationRequestContext : BaseValidatingContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public HandleRevocationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, options, request) {
            Ticket = ticket;
            Validate();
        }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether
        /// the token was successfully revoked.
        /// </summary>
        public bool Revoked { get; set; }
    }
}
