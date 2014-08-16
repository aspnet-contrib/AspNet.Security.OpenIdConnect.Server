/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Owin.Security.OpenIdConnect.Server.Messages;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in validating an OpenIdConnect token request.
    /// </summary>
    public class OpenIdConnectValidateTokenRequestContext : BaseValidatingContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectValidateTokenRequestContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tokenRequest"></param>
        /// <param name="clientContext"></param>
        public OpenIdConnectValidateTokenRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            TokenEndpointRequest tokenRequest,
            BaseValidatingClientContext clientContext) : base(context, options) {
            TokenRequest = tokenRequest;
            ClientContext = clientContext;
        }

        /// <summary>
        /// Gets the token request data.
        /// </summary>
        public TokenEndpointRequest TokenRequest { get; private set; }

        /// <summary>
        /// Gets information about the client.
        /// </summary>
        public BaseValidatingClientContext ClientContext { get; private set; }
    }
}
