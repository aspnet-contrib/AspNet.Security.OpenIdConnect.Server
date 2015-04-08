/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised before the authorization server handles
    /// the request made to the token validation endpoint.
    /// </summary>
    public sealed class ValidationEndpointNotification : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context.
        /// </summary>
        internal ValidationEndpointNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options) {
            ValidationRequest = request;
            Claims = new List<Claim>();
        }

        /// <summary>
        /// Gets the validation request.
        /// </summary>
        public OpenIdConnectMessage ValidationRequest { get; private set; }

        /// <summary>
        /// Gets the list of claims returned to the caller.
        /// </summary>
        public IList<Claim> Claims { get; private set; }
    }
}
