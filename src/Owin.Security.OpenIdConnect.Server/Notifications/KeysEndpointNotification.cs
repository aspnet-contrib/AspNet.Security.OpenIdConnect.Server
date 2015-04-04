/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the JWKS metadata endpoint.
    /// </summary>
    public sealed class KeysEndpointNotification : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal KeysEndpointNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
            Keys = new List<JsonWebKey>();
        }

        /// <summary>
        /// Gets a list of the JSON Web Keys found by the authorization server.
        /// </summary>
        public IList<JsonWebKey> Keys { get; private set; }
    }
}
