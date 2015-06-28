/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public sealed class ProfileEndpointContext : BaseControlContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        internal ProfileEndpointContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            AuthenticationTicket ticket)
            : base(context, options) {
            AuthenticationTicket = ticket;
            Request = request;
        }

        /// <summary>
        /// Gets the userinfo request.
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the list of claims returned to the client application.
        /// </summary>
        public IDictionary<string, string> Claims { get; } = new Dictionary<string, string>();
    }
}
