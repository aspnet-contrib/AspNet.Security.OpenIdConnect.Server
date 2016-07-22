/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the token revocation endpoint.
    /// </summary>
    public class HandleRevocationRequestContext : BaseValidatingContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        public HandleRevocationRequestContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectRequest request,
            AuthenticationTicket ticket)
            : base(context, options) {
            Request = request;
            Ticket = ticket;
            Validate();
        }

        /// <summary>
        /// Gets the revocation request.
        /// </summary>
        public new OpenIdConnectRequest Request { get; }

        /// <summary>
        /// Gets or sets a boolean indicating whether
        /// the token was successfully revoked.
        /// </summary>
        public bool Revoked { get; set; }
    }
}
