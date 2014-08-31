/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in validating an OpenIdConnect authorization request.
    /// </summary>
    public sealed class OpenIdConnectValidateAuthorizationRequestContext : BaseValidatingContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectValidateAuthorizationRequestContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="authorizationRequest"></param>
        /// <param name="clientContext"></param>
        internal OpenIdConnectValidateAuthorizationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage authorizationRequest,
            OpenIdConnectValidateClientRedirectUriContext clientContext)
            : base(context, options) {
            ClientContext = clientContext;
            AuthorizationRequest = authorizationRequest;
        }

        /// <summary>
        /// Gets the authorization request.
        /// </summary>
        public OpenIdConnectMessage AuthorizationRequest { get; private set; }

        /// <summary>
        /// Gets the client context. 
        /// </summary>
        public OpenIdConnectValidateClientRedirectUriContext ClientContext { get; private set; }
    }
}
