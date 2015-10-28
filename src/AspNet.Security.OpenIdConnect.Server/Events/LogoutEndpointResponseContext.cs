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
    /// Provides context information when processing a logout response.
    /// </summary>
    public sealed class LogoutEndpointResponseContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="LogoutEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="response"></param>
        internal LogoutEndpointResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            OpenIdConnectMessage response)
            : base(context) {
            Options = options;
            Request = request;
            Response = response;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the logout request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the logout response. 
        /// </summary>
        public new OpenIdConnectMessage Response { get; }
    }
}
