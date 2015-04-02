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
    public sealed class ValidateAuthorizationRequestNotification : BaseValidatingNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateAuthorizationRequestNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="authorizationRequest"></param>
        /// <param name="clientContext"></param>
        internal ValidateAuthorizationRequestNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage authorizationRequest,
            ValidateClientRedirectUriNotification clientContext)
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
        public ValidateClientRedirectUriNotification ClientContext { get; private set; }
    }
}
