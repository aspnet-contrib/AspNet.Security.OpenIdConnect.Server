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
    /// writing the token validation to the response stream.
    /// </summary>
    public sealed class ValidationEndpointResponseContext : BaseControlContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal ValidationEndpointResponseContext(
            HttpContext httpContext,
            OpenIdConnectServerOptions options,
            JObject payload)
            : base(httpContext, options) {
            Payload = payload;
        }

        /// <summary>
        /// Gets the JSON payload returned to the caller.
        /// </summary>
        public JObject Payload { get; private set; }
    }
}
