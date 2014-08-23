/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;
using Owin.Security.OpenIdConnect.Server.Messages;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// An event raised after the Authorization Server has processed the request, but before it is passed on to the web application.
    /// Calling RequestCompleted will prevent the request from passing on to the web application.
    /// </summary>
    public class OpenIdConnectAuthorizationEndpointContext : EndpointContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Creates an instance of this context
        /// </summary>
        public OpenIdConnectAuthorizationEndpointContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectAuthorizationRequest authorizationRequest)
            : base(context, options) {
            AuthorizationRequest = authorizationRequest;
        }

        /// <summary>
        /// Gets OpenIdConnect authorization request data.
        /// </summary>
        public OpenIdConnectAuthorizationRequest AuthorizationRequest { get; private set; }
    }
}
