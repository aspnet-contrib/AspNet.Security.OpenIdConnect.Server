/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server starts
    /// writing the token status/metadata to the response stream.
    /// </summary>
    public sealed class ValidationEndpointResponseContext : BaseControlContext {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal ValidationEndpointResponseContext(
            HttpContext context,
            OpenIdConnectServerOptions options,
            JObject payload)
            : base(context) {
            Options = options;
            Payload = payload;
        }

        /// <summary>
        /// Gets the options used by the OpenID Connect server.
        /// </summary>
        public OpenIdConnectServerOptions Options { get; }

        /// <summary>
        /// Gets the JSON payload returned to the caller.
        /// </summary>
        public JObject Payload { get; private set; }
    }
}
