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
    public class OpenIdConnectValidateAuthorizationRequestContext : BaseValidatingContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectValidateAuthorizationRequestContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="authorizationRequest"></param>
        /// <param name="clientContext"></param>
        public OpenIdConnectValidateAuthorizationRequestContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage authorizationRequest,
            OpenIdConnectValidateClientRedirectUriContext clientContext)
            : base(context, options) {
            ClientContext = clientContext;
            AuthorizationRequest = authorizationRequest;
        }

        /// <summary>
        /// Gets OpenIdConnect authorization request data.
        /// </summary>
        public OpenIdConnectMessage AuthorizationRequest { get; private set; }

        /// <summary>
        /// Gets data about the OpenIdConnect client. 
        /// </summary>
        public OpenIdConnectValidateClientRedirectUriContext ClientContext { get; private set; }
    }
}
