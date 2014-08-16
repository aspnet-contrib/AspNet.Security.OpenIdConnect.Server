/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/AspNet-OpenIdConnect-Server/Owin.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.OpenIdConnect.Server {
    /// <summary>
    /// Provides context information when handling an OpenIdConnect authorization code grant.
    /// </summary>
    public class OpenIdConnectGrantAuthorizationCodeContext : BaseValidatingTicketContext<OpenIdConnectServerOptions> {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectGrantAuthorizationCodeContext"/> class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        /// <param name="ticket"></param>
        public OpenIdConnectGrantAuthorizationCodeContext(
            IOwinContext context,
            OpenIdConnectServerOptions options,
            AuthenticationTicket ticket) : base(context, options, ticket) {
        }
    }
}
