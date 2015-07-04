/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the JWKS metadata endpoint.
    /// </summary>
    public sealed class CryptographyEndpointNotification : BaseNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal CryptographyEndpointNotification(
            HttpContext context,
            OpenIdConnectServerOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// Gets a list of the JSON Web Keys found by the authorization server.
        /// </summary>
        public IList<JsonWebKey> Keys { get; } = new List<JsonWebKey>();
    }
}
