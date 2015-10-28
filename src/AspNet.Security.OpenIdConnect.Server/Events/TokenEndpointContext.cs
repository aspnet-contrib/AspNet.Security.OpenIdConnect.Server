/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when processing an OpenIdConnect token request.
    /// </summary>
    public sealed class TokenEndpointContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenEndpointContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="ticket"></param>
        internal TokenEndpointContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            AuthenticationTicket ticket)
            : base(context) {
            Options = options;
            Request = request;
            Ticket = ticket;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }

        /// <summary>
        /// Gets information about the token endpoint request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }
    }
}
