/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server starts
    /// writing the JWKS metadata to the response stream.
    /// </summary>
    public sealed class CryptographyEndpointResponseNotification : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal CryptographyEndpointResponseNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            JObject payload)
            : base(context, options) {
            Payload = payload;
        }

        /// <summary>
        /// Gets the JSON payload returned to the client application.
        /// </summary>
        public JObject Payload { get; private set; }
    }
}
