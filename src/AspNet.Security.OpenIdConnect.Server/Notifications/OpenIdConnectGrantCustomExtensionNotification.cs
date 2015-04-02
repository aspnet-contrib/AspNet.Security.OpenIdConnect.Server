/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when handling OpenIdConnect extension grant types.
    /// </summary>
    public sealed class OpenIdConnectGrantCustomExtensionNotification : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantCustomExtensionNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="tokenRequest"></param>
        internal OpenIdConnectGrantCustomExtensionNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage tokenRequest)
            : base(context, options, null) {
            TokenRequest = tokenRequest;
        }

        /// <summary>
        /// Gets the client_id parameter.
        /// </summary>
        public string ClientId => TokenRequest.ClientId;

        /// <summary>
        /// Gets the grant_type parameter.
        /// </summary>
        public string GrantType => TokenRequest.GrantType;

        /// <summary>
        /// Gets the token request.
        /// </summary>
        public OpenIdConnectMessage TokenRequest { get; private set; }
    }
}
