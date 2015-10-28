/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used at the end of a token-endpoint-request.
    /// </summary>
    public sealed class TokenEndpointResponseContext : BaseControlContext {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenEndpointResponseContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        /// <param name="request"></param>
        /// <param name="payload"></param>
        internal TokenEndpointResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket,
            OpenIdConnectMessage request,
            JObject payload)
            : base(context) {
            Options = options;
            AuthenticationTicket = ticket;
            Request = request;
            Payload = payload;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the token request. 
        /// </summary>
        public new OpenIdConnectMessage Request { get; }

        /// <summary>
        /// Gets the JSON payload returned to the client
        /// application as part of the token response.
        /// </summary>
        public JObject Payload { get; }
    }
}
