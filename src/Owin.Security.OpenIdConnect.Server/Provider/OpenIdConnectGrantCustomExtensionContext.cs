/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information used when handling OpenIdConnect extension grant types.
    /// </summary>
    public class OpenIdConnectGrantCustomExtensionContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantCustomExtensionContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="clientId"></param>
        /// <param name="grantType"></param>
        /// <param name="parameters"></param>
        public OpenIdConnectGrantCustomExtensionContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            string clientId,
            string grantType,
            IReadableStringCollection parameters)
            : base(context, options, null) {
            ClientId = clientId;
            GrantType = grantType;
            Parameters = parameters;
        }

        /// <summary>
        /// Gets the OpenIdConnect client id.
        /// </summary>
        public string ClientId { get; private set; }

        /// <summary>
        /// Gets the name of the OpenIdConnect extension grant type.
        /// </summary>
        public string GrantType { get; private set; }

        /// <summary>
        /// Gets a list of additional parameters from the token request.
        /// </summary>
        public IReadableStringCollection Parameters { get; private set; }
    }
}
