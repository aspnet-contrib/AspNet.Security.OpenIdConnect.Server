/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used in validating an OpenIdConnect token request.
    /// </summary>
    public sealed class ValidateTokenRequestNotification : BaseValidatingNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateTokenRequestNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        /// <param name="clientContext"></param>
        internal ValidateTokenRequestNotification(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request,
            BaseValidatingClientNotification clientContext)
            : base(context, options) {
            TokenRequest = request;
            ClientContext = clientContext;
        }

        /// <summary>
        /// Gets the token request data.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }

        /// <summary>
        /// Gets information about the client.
        /// </summary>
        public BaseValidatingClientNotification ClientContext { get; private set; }
    }
}
