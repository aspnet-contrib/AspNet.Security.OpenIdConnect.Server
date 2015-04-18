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
    public sealed class GrantCustomExtensionNotification : BaseValidatingTicketNotification<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="GrantCustomExtensionNotification"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="request"></param>
        internal GrantCustomExtensionNotification(
            HttpContext context,
            OpenIdConnectServerOptions options,
            OpenIdConnectMessage request)
            : base(context, options, null) {
            TokenRequest = request;
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
        public OpenIdConnectMessage TokenRequest { get; }
    }
}
